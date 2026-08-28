import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { describe, expect, it } from "vitest";
import { waitForAuthorizationCode } from "../src/oauth.js";

const PORT = 39871;
const REDIRECT_URI = `http://127.0.0.1:${PORT}/auth/callback`;
type RequestHandler = (request: IncomingMessage, response: ServerResponse) => void;

interface FakeResponse {
  status: number;
  text: string;
}

class FakeServer {
  listening = false;
  private readonly errorListeners: Array<(error: Error) => void> = [];

  constructor(
    readonly port: number,
    readonly handler: RequestHandler,
    private readonly allServers: FakeServer[],
  ) {}

  close(): this {
    this.listening = false;
    return this;
  }

  on(event: string, listener: (error: Error) => void): this {
    if (event === "error") this.errorListeners.push(listener);
    return this;
  }

  listen(): this {
    const conflict = this.allServers.some(
      (server) => server !== this && server.port === this.port && server.listening,
    );
    if (conflict) {
      const error = Object.assign(new Error("address already in use"), { code: "EADDRINUSE" });
      queueMicrotask(() => {
        for (const listener of this.errorListeners) listener(error);
      });
    } else {
      this.listening = true;
    }
    return this;
  }
}

function loopbackHarness(): {
  serverFactory: typeof import("node:http").createServer;
  hit: (pathAndQuery: string) => Promise<FakeResponse>;
} {
  const servers: FakeServer[] = [];
  const serverFactory = ((handler: RequestHandler) => {
    const server = new FakeServer(PORT, handler, servers);
    servers.push(server);
    return server as unknown as Server;
  }) as typeof import("node:http").createServer;

  const hit = async (pathAndQuery: string): Promise<FakeResponse> => {
    const server = servers.find((candidate) => candidate.listening);
    if (server === undefined) throw new Error("No loopback server is listening.");

    return await new Promise<FakeResponse>((resolve) => {
      let status = 200;
      let text = "";
      const response = {
        writeHead(nextStatus: number) {
          status = nextStatus;
          return response;
        },
        end(body?: string, callback?: () => void) {
          text = body ?? "";
          callback?.();
          resolve({ status, text });
          return response;
        },
      } as unknown as ServerResponse;
      server.handler({ url: pathAndQuery } as IncomingMessage, response);
    });
  };

  return { serverFactory, hit };
}

describe("waitForAuthorizationCode", () => {
  it("resolves the code and serves a completion page", async () => {
    const { serverFactory, hit } = loopbackHarness();
    const codePromise = waitForAuthorizationCode(
      { redirectUri: REDIRECT_URI, expectedState: "expected-state", timeoutMs: 5000 },
      serverFactory,
    );
    const response = await hit("/auth/callback?code=the-code&state=expected-state");
    expect(response.status).toBe(200);
    expect(response.text).toContain("login complete");
    await expect(codePromise).resolves.toBe("the-code");
  });

  it("ignores a wrong-state callback and still resolves the real one", async () => {
    const { serverFactory, hit } = loopbackHarness();
    const codePromise = waitForAuthorizationCode(
      { redirectUri: REDIRECT_URI, expectedState: "expected-state", timeoutMs: 5000 },
      serverFactory,
    );
    expect((await hit("/auth/callback?code=stolen&state=WRONG")).status).toBe(404);
    expect((await hit("/auth/callback?code=the-code&state=expected-state")).status).toBe(200);
    await expect(codePromise).resolves.toBe("the-code");
  });

  it("ignores a spoofed error without the state", async () => {
    const { serverFactory, hit } = loopbackHarness();
    const codePromise = waitForAuthorizationCode(
      { redirectUri: REDIRECT_URI, expectedState: "expected-state", timeoutMs: 5000 },
      serverFactory,
    );
    expect(
      (await hit("/auth/callback?error=access_denied&error_description=User+cancelled")).status,
    ).toBe(404);
    await hit("/auth/callback?code=the-code&state=expected-state");
    await expect(codePromise).resolves.toBe("the-code");
  });

  it("rejects a genuine Cognito error that carries the correct state", async () => {
    const { serverFactory, hit } = loopbackHarness();
    const codePromise = waitForAuthorizationCode(
      { redirectUri: REDIRECT_URI, expectedState: "expected-state", timeoutMs: 5000 },
      serverFactory,
    );
    await hit(
      "/auth/callback?error=access_denied&error_description=User+cancelled&state=expected-state",
    );
    await expect(codePromise).rejects.toThrow(/access_denied/);
  });

  it("rejects with a port hint when the port is taken", async () => {
    const { serverFactory, hit } = loopbackHarness();
    const first = waitForAuthorizationCode(
      { redirectUri: REDIRECT_URI, expectedState: "a", timeoutMs: 5000 },
      serverFactory,
    );
    const second = waitForAuthorizationCode(
      { redirectUri: REDIRECT_URI, expectedState: "b", timeoutMs: 5000 },
      serverFactory,
    );
    await expect(second).rejects.toThrow(/in use/);
    await hit("/auth/callback?code=x&state=a");
    await expect(first).resolves.toBe("x");
  });

  it("times out when no callback arrives", async () => {
    const { serverFactory } = loopbackHarness();
    await expect(
      waitForAuthorizationCode(
        { redirectUri: REDIRECT_URI, expectedState: "s", timeoutMs: 10 },
        serverFactory,
      ),
    ).rejects.toThrow(/timed out/);
  });
});
