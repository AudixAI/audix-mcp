import type { Config } from "../src/config.js";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  configure: vi.fn(),
  generateClient: vi.fn(),
  observers: new Map<string, { error(error: unknown): void; next(value: unknown): void }>(),
  unsubscribe: vi.fn(),
}));

vi.mock("aws-amplify", () => ({ Amplify: { configure: mocks.configure } }));
vi.mock("aws-amplify/api", () => ({
  generateClient: mocks.generateClient.mockImplementation(() => ({
    graphql: ({ variables }: { variables: { event: string } }) => ({
      subscribe: (observer: { error(error: unknown): void; next(value: unknown): void }) => {
        mocks.observers.set(variables.event, observer);
        return { closed: false, unsubscribe: mocks.unsubscribe };
      },
    }),
  })),
}));

import { createUserPoolTokenProvider, RealtimeMonitor } from "../src/realtime.js";

const CONFIG: Config = {
  apiBaseUrl: "https://api.example",
  appSyncGraphqlEndpoint: "https://graphql.example/graphql",
  awsRegion: "us-east-1",
  cognitoClientId: "client-id",
  cognitoDomain: "https://auth.example",
  credentialsPath: "/private/credentials.json",
  projectRoot: "/private/project",
  oauthScopes: "openid email",
  redirectUri: "http://127.0.0.1:49673/auth/callback",
  uploadBucketOrigin: "https://bucket.s3.amazonaws.com",
};

const SCAN_ID = "33333333-3333-4333-8333-333333333333";
const TARGET_ID = "11111111-1111-4111-8111-111111111111";
const ACCESS_TOKEN =
  "eyJhbGciOiJSUzI1NiJ9." +
  "eyJzdWIiOiJjb2duaXRvLXN1YmplY3QiLCJ0b2tlbl91c2UiOiJhY2Nlc3MifQ." +
  "signature";

function envelope(event: string, message: Record<string, unknown>): unknown {
  return {
    data: {
      onEventPublished: {
        eventId: "cognito-subject",
        event,
        message: JSON.stringify(message),
      },
    },
  };
}

describe("RealtimeMonitor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.observers.clear();
  });

  it("does not install subscriptions for an invalidated session", async () => {
    const monitor = new RealtimeMonitor(CONFIG, async () => ACCESS_TOKEN, vi.fn());

    await expect(monitor.start("old-subject", () => false)).rejects.toThrow(/session changed/);
    expect(mocks.generateClient).not.toHaveBeenCalled();
    expect(mocks.configure).not.toHaveBeenCalled();
  });

  it("forwards only closed safe fields for a tracked scan", async () => {
    const notify = vi.fn().mockResolvedValue(undefined);
    const monitor = new RealtimeMonitor(CONFIG, async () => ACCESS_TOKEN, notify);
    monitor.track({ id: SCAN_ID, status: "running" });
    await monitor.start("cognito-subject");

    expect(mocks.generateClient).toHaveBeenCalledWith({
      authMode: "userPool",
      endpoint: CONFIG.appSyncGraphqlEndpoint,
    });
    const libraryOptions = mocks.configure.mock.calls[0]?.[1] as {
      Auth?: { tokenProvider?: ReturnType<typeof createUserPoolTokenProvider> };
    };
    await expect(libraryOptions.Auth?.tokenProvider?.getTokens()).resolves.toMatchObject({
      accessToken: { payload: { sub: "cognito-subject", token_use: "access" } },
    });

    mocks.observers.get("scan.progress_changed")?.next(
      envelope("scan.progress_changed", {
        messageType: "scanProgressChanged",
        scanId: SCAN_ID,
        targetId: TARGET_ID,
        stage: "modeling_state",
      }),
    );

    await vi.waitFor(() =>
      expect(notify).toHaveBeenCalledWith({
        type: "audix.scan.progress",
        scanId: SCAN_ID,
        targetId: TARGET_ID,
        stage: "modeling_state",
      }),
    );
  });

  it("does not forward events for scans this MCP process is not tracking", async () => {
    const notify = vi.fn().mockResolvedValue(undefined);
    const monitor = new RealtimeMonitor(CONFIG, async () => ACCESS_TOKEN, notify);
    await monitor.start("cognito-subject");

    mocks.observers.get("scan.status_changed")?.next(
      envelope("scan.status_changed", {
        messageType: "scanStatusChanged",
        scanId: SCAN_ID,
        targetId: TARGET_ID,
        status: "success",
      }),
    );

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(notify).not.toHaveBeenCalled();
  });

  it("captures an event that races ahead of the startScan response", async () => {
    const notify = vi.fn().mockResolvedValue(undefined);
    const monitor = new RealtimeMonitor(CONFIG, async () => ACCESS_TOKEN, notify);
    monitor.trackTarget(TARGET_ID);
    await monitor.start("cognito-subject");

    mocks.observers.get("scan.status_changed")?.next(
      envelope("scan.status_changed", {
        messageType: "scanStatusChanged",
        scanId: SCAN_ID,
        targetId: TARGET_ID,
        status: "running",
      }),
    );

    await vi.waitFor(() =>
      expect(notify).toHaveBeenCalledWith({
        type: "audix.scan.status",
        scanId: SCAN_ID,
        targetId: TARGET_ID,
        status: "running",
      }),
    );
  });

  it("fails closed when an event contains an unexpected field", async () => {
    const notify = vi.fn().mockResolvedValue(undefined);
    const monitor = new RealtimeMonitor(CONFIG, async () => ACCESS_TOKEN, notify);
    monitor.track({ id: SCAN_ID, status: "running" });
    await monitor.start("cognito-subject");

    mocks.observers.get("scan.progress_changed")?.next(
      envelope("scan.progress_changed", {
        messageType: "scanProgressChanged",
        scanId: SCAN_ID,
        targetId: TARGET_ID,
        stage: "modeling_state",
        internalTrace: "must-not-cross-boundary",
      }),
    );

    await vi.waitFor(() => expect(mocks.unsubscribe).toHaveBeenCalled());
    expect(notify).not.toHaveBeenCalled();
  });
});
