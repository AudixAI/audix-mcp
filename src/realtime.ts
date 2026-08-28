import { Amplify } from "aws-amplify";
import { generateClient } from "aws-amplify/api";
import { decodeJWT, type TokenProvider } from "aws-amplify/auth";
import { z } from "zod";
import {
  scanProgressStageSchema,
  scanStatusSchema,
  type ScanWire,
} from "./api.js";
import type { Config } from "./config.js";

const ON_EVENT_PUBLISHED = `
  subscription OnEventPublished($eventId: ID!, $event: String!) {
    onEventPublished(eventId: $eventId, event: $event) {
      eventId
      event
      message
    }
  }
`;

const realtimeEventTypeSchema = z.enum([
  "scan.status_changed",
  "scan.progress_changed",
]);

const eventPayloadSchema = z.strictObject({
  eventId: z.string().min(1),
  event: realtimeEventTypeSchema,
  message: z.string().min(1),
});

const subscriptionEnvelopeSchema = z.object({
  data: z.object({ onEventPublished: eventPayloadSchema }),
});

const statusMessageSchema = z.strictObject({
  messageType: z.literal("scanStatusChanged"),
  scanId: z.uuid(),
  targetId: z.uuid(),
  status: scanStatusSchema,
});

const progressMessageSchema = z.strictObject({
  messageType: z.literal("scanProgressChanged"),
  scanId: z.uuid(),
  targetId: z.uuid(),
  stage: scanProgressStageSchema,
});

export type SafeScanNotification =
  | {
      type: "audix.scan.status";
      scanId: string;
      targetId: string;
      status: z.infer<typeof scanStatusSchema>;
    }
  | {
      type: "audix.scan.progress";
      scanId: string;
      targetId: string;
      stage: z.infer<typeof scanProgressStageSchema>;
    };

interface SubscriptionLike {
  closed: boolean;
  unsubscribe(): void;
}

type NotificationSink = (event: SafeScanNotification) => Promise<void>;

/** Supply the MCP-managed Cognito session to Amplify's WebSocket auth path. */
export function createUserPoolTokenProvider(
  getAccessToken: () => Promise<string>,
): TokenProvider {
  return {
    async getTokens() {
      return { accessToken: decodeJWT(await getAccessToken()) };
    },
  };
}

/**
 * Owns user-bound AppSync subscriptions for the lifetime of the stdio server.
 * Only closed, customer-safe scan fields cross the MCP notification boundary.
 */
export class RealtimeMonitor {
  private eventId: string | undefined;
  private subscriptions: SubscriptionLike[] = [];
  private readonly trackedScans = new Set<string>();
  private readonly trackedTargets = new Set<string>();
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly config: Config,
    private readonly getAccessToken: () => Promise<string>,
    private readonly notify: NotificationSink,
  ) {}

  track(
    scan: Pick<ScanWire, "id"> & Partial<Pick<ScanWire, "status" | "targetId">>,
  ): void {
    if (scan.targetId !== undefined) this.trackedTargets.delete(scan.targetId);
    if (
      scan.status !== undefined &&
      ["success", "failed", "cancelled"].includes(scan.status)
    ) {
      this.trackedScans.delete(scan.id);
      return;
    }
    this.trackedScans.add(scan.id);
  }

  /** Track the first scan event for a target before startScan returns its id. */
  trackTarget(targetId: string): void {
    this.trackedTargets.add(targetId);
  }

  async start(eventId: string, isCurrentSession: () => boolean = () => true): Promise<void> {
    if (!isCurrentSession()) {
      throw new Error("Realtime start cancelled because the authenticated session changed.");
    }
    if (
      this.eventId === eventId &&
      this.subscriptions.length === 2 &&
      this.subscriptions.every((subscription) => !subscription.closed)
    ) {
      return;
    }
    this.stopSubscriptions();
    this.eventId = eventId;
    this.clearReconnect();

    Amplify.configure(
      {
        API: {
          GraphQL: {
            defaultAuthMode: "userPool",
            endpoint: this.config.appSyncGraphqlEndpoint,
            region: this.config.awsRegion,
          },
        },
      },
      { Auth: { tokenProvider: createUserPoolTokenProvider(this.getAccessToken) } },
    );
    const client = generateClient({
      authMode: "userPool",
      endpoint: this.config.appSyncGraphqlEndpoint,
    });

    for (const eventType of realtimeEventTypeSchema.options) {
      const operation = client.graphql({
        query: ON_EVENT_PUBLISHED,
        variables: { event: eventType, eventId },
      });
      if (!("subscribe" in operation)) {
        this.stop();
        throw new Error("AppSync subscription did not return an observable.");
      }
      this.subscriptions.push(
        operation.subscribe({
          error: (error: unknown) => {
            console.error(
              `[audix-mcp] realtime ${eventType} subscription failed: ${errorMessage(error)}`,
            );
            this.stopSubscriptions();
            this.scheduleReconnect();
          },
          next: (response: unknown) => {
            void this.handle(response, eventType, eventId).catch((error: unknown) => {
              console.error(`[audix-mcp] realtime event rejected: ${errorMessage(error)}`);
              this.stop();
            });
          },
        }),
      );
    }
    if (!isCurrentSession()) {
      this.stop();
      throw new Error("Realtime start cancelled because the authenticated session changed.");
    }
  }

  stop(): void {
    this.clearReconnect();
    this.eventId = undefined;
    this.reconnectAttempt = 0;
    this.stopSubscriptions();
  }

  private stopSubscriptions(): void {
    const active = this.subscriptions;
    this.subscriptions = [];
    for (const subscription of active) subscription.unsubscribe();
  }

  private clearReconnect(): void {
    if (this.reconnectTimer === undefined) return;
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
  }

  private scheduleReconnect(): void {
    if (this.eventId === undefined || this.reconnectTimer !== undefined) return;
    const delay = Math.min(1_000 * 2 ** this.reconnectAttempt, 30_000);
    this.reconnectAttempt = Math.min(this.reconnectAttempt + 1, 5);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      const eventId = this.eventId;
      if (eventId === undefined) return;
      void this.start(eventId).catch((error: unknown) => {
        console.error(`[audix-mcp] realtime reconnect failed: ${errorMessage(error)}`);
        this.scheduleReconnect();
      });
    }, delay);
    this.reconnectTimer.unref?.();
  }

  private async handle(
    response: unknown,
    expectedType: z.infer<typeof realtimeEventTypeSchema>,
    expectedEventId: string,
  ): Promise<void> {
    const payload = subscriptionEnvelopeSchema.parse(response).data.onEventPublished;
    this.reconnectAttempt = 0;
    if (payload.eventId !== expectedEventId || payload.event !== expectedType) {
      throw new Error("AppSync returned an event outside the active subscription.");
    }
    const decoded: unknown = JSON.parse(payload.message);
    if (payload.event === "scan.status_changed") {
      const message = statusMessageSchema.parse(decoded);
      if (!this.acceptTrackedEvent(message.scanId, message.targetId)) return;
      await this.notify({
        type: "audix.scan.status",
        scanId: message.scanId,
        targetId: message.targetId,
        status: message.status,
      });
      if (["success", "failed", "cancelled"].includes(message.status)) {
        this.trackedScans.delete(message.scanId);
      }
      return;
    }
    const message = progressMessageSchema.parse(decoded);
    if (!this.acceptTrackedEvent(message.scanId, message.targetId)) return;
    await this.notify({
      type: "audix.scan.progress",
      scanId: message.scanId,
      targetId: message.targetId,
      stage: message.stage,
    });
  }

  private acceptTrackedEvent(scanId: string, targetId: string): boolean {
    if (this.trackedScans.has(scanId)) return true;
    if (!this.trackedTargets.delete(targetId)) return false;
    this.trackedScans.add(scanId);
    return true;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
