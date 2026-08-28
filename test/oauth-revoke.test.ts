import { afterEach, describe, expect, it, vi } from "vitest";
import {
  exchangeCodeForTokens,
  MAX_OAUTH_RESPONSE_BYTES,
  revokeRefreshToken,
} from "../src/oauth.js";

describe("revokeRefreshToken", () => {
  afterEach(() => vi.restoreAllMocks());

  it("posts the refresh token to the issuer without following redirects", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));

    await revokeRefreshToken({
      cognitoDomain: "https://auth.example",
      clientId: "public-client",
      refreshToken: "refresh-token",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      new URL("https://auth.example/oauth2/revoke"),
      expect.objectContaining({
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "token=refresh-token&client_id=public-client",
        redirect: "manual",
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("aborts a stalled revocation request at the configured deadline", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      }),
    );

    await expect(
      revokeRefreshToken({
        cognitoDomain: "https://auth.example",
        clientId: "public-client",
        refreshToken: "refresh-token",
        requestTimeoutMs: 1,
      }),
    ).rejects.toBeDefined();
  });

  it("rejects an oversized token response before parsing it", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ padding: "x".repeat(MAX_OAUTH_RESPONSE_BYTES) }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    await expect(
      exchangeCodeForTokens({
        cognitoDomain: "https://auth.example",
        clientId: "public-client",
        redirectUri: "http://127.0.0.1:49673/auth/callback",
        code: "code",
        verifier: "verifier",
      }),
    ).rejects.toThrow(/exceeds/i);
  });
});
