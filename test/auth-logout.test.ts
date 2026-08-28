import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Config } from "../src/config.js";

const mocks = vi.hoisted(() => ({
  deleteCredentials: vi.fn(),
  exchangeCodeForTokens: vi.fn(),
  loadCredentials: vi.fn(),
  revokeRefreshToken: vi.fn(),
  refreshAccessToken: vi.fn(),
  saveCredentials: vi.fn(),
  waitForAuthorizationCode: vi.fn(),
}));

vi.mock("../src/token-store.js", () => ({
  deleteCredentials: mocks.deleteCredentials,
  loadCredentials: mocks.loadCredentials,
  saveCredentials: mocks.saveCredentials,
}));

vi.mock("../src/oauth.js", async () => {
  const actual = await vi.importActual<typeof import("../src/oauth.js")>("../src/oauth.js");
  return {
    ...actual,
    exchangeCodeForTokens: mocks.exchangeCodeForTokens,
    revokeRefreshToken: mocks.revokeRefreshToken,
    refreshAccessToken: mocks.refreshAccessToken,
    waitForAuthorizationCode: mocks.waitForAuthorizationCode,
  };
});

import { AuthManager, NotLoggedInError } from "../src/auth-manager.js";

const CONFIG: Config = {
  apiBaseUrl: "https://api.example",
  cognitoDomain: "https://auth.example",
  cognitoClientId: "configured-client",
  appSyncGraphqlEndpoint: "https://graphql.example/graphql",
  awsRegion: "us-east-1",
  redirectUri: "http://127.0.0.1:49673/auth/callback",
  oauthScopes: "openid",
  credentialsPath: "/private/credentials.json",
  projectRoot: "/private/project",
  uploadBucketOrigin: "https://bucket.s3.amazonaws.com",
};

const CREDENTIALS = {
  refreshToken: "refresh-token",
  clientId: "issuing-client",
  email: "dev@example.com",
  obtainedAt: "2026-08-23T12:00:00.000Z",
};

describe("AuthManager.logout", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.loadCredentials.mockResolvedValue(CREDENTIALS);
    mocks.revokeRefreshToken.mockResolvedValue(undefined);
    mocks.deleteCredentials.mockResolvedValue(undefined);
    mocks.exchangeCodeForTokens.mockResolvedValue({
      access_token: "login-access",
      refresh_token: "login-refresh",
      expires_in: 3600,
    });
    mocks.saveCredentials.mockResolvedValue(undefined);
    mocks.waitForAuthorizationCode.mockResolvedValue("authorization-code");
  });

  it("revokes the stored refresh token before deleting local credentials", async () => {
    const order: string[] = [];
    mocks.revokeRefreshToken.mockImplementation(async () => {
      order.push("revoke");
    });
    mocks.deleteCredentials.mockImplementation(async () => {
      order.push("delete");
    });

    await new AuthManager(CONFIG).logout();

    expect(mocks.revokeRefreshToken).toHaveBeenCalledWith({
      cognitoDomain: CONFIG.cognitoDomain,
      clientId: CREDENTIALS.clientId,
      refreshToken: CREDENTIALS.refreshToken,
    });
    expect(mocks.deleteCredentials).toHaveBeenCalledWith(CONFIG.credentialsPath);
    expect(order).toEqual(["revoke", "delete"]);
  });

  it("always deletes local state and surfaces an issuer revocation failure", async () => {
    mocks.revokeRefreshToken.mockRejectedValue(new Error("issuer unavailable"));

    await expect(new AuthManager(CONFIG).logout()).rejects.toThrow(
      /Local credentials were cleared.*revocation failed.*issuer unavailable/,
    );
    expect(mocks.deleteCredentials).toHaveBeenCalledOnce();
  });

  it("discards a refresh that overlaps a logout — no token survives (NEW-004)", async () => {
    // Credentials whose clientId matches the config so the refresh path runs.
    mocks.loadCredentials.mockResolvedValue({ ...CREDENTIALS, clientId: CONFIG.cognitoClientId });

    // Hold the refresh in flight until we release it, so a logout can land mid-refresh.
    let releaseRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    });
    mocks.refreshAccessToken.mockImplementation(async () => {
      await refreshGate;
      return { access_token: "raced-access", expires_in: 3600 };
    });

    const manager = new AuthManager(CONFIG);
    const inFlight = manager.getAccessToken(); // captures generation, then awaits refresh
    const loggingOut = manager.logout(); // bumps generation while refresh is held
    releaseRefresh();
    await loggingOut;

    // The token minted across the logout must NOT be returned or cached.
    await expect(inFlight).rejects.toBeInstanceOf(NotLoggedInError);
    // And the manager is genuinely logged out afterwards (credentials gone).
    mocks.loadCredentials.mockResolvedValue(undefined);
    await expect(manager.getAccessToken()).rejects.toBeInstanceOf(NotLoggedInError);
  });

  it("does not persist a login that started before logout", async () => {
    let releaseExchange!: () => void;
    const exchangeGate = new Promise<void>((resolve) => {
      releaseExchange = resolve;
    });
    mocks.exchangeCodeForTokens.mockImplementation(async () => {
      await exchangeGate;
      return {
        access_token: "raced-login-access",
        refresh_token: "raced-login-refresh",
        expires_in: 3600,
      };
    });

    const manager = new AuthManager(CONFIG, () => undefined);
    const loggingIn = manager.login();
    await vi.waitFor(() => expect(mocks.exchangeCodeForTokens).toHaveBeenCalledOnce());

    const loggingOut = manager.logout();
    await loggingOut;
    expect(mocks.saveCredentials).not.toHaveBeenCalled();
    releaseExchange();

    await expect(loggingIn).rejects.toBeInstanceOf(NotLoggedInError);
    expect(mocks.saveCredentials).not.toHaveBeenCalled();
    expect(mocks.deleteCredentials).toHaveBeenCalledWith(CONFIG.credentialsPath);
  });

  it("deletes credentials when logout begins during login persistence", async () => {
    let releaseSave!: () => void;
    mocks.saveCredentials.mockImplementation(
      () => new Promise<void>((resolve) => (releaseSave = resolve)),
    );

    const manager = new AuthManager(CONFIG, () => undefined);
    const loggingIn = manager.login();
    await vi.waitFor(() => expect(mocks.saveCredentials).toHaveBeenCalledOnce());

    const loggingOut = manager.logout();
    releaseSave();

    await expect(loggingIn).rejects.toBeInstanceOf(NotLoggedInError);
    await loggingOut;
    expect(mocks.deleteCredentials).toHaveBeenCalledWith(CONFIG.credentialsPath);
    mocks.loadCredentials.mockResolvedValue(undefined);
    await expect(manager.getAccessToken()).rejects.toBeInstanceOf(NotLoggedInError);
  });

  it("persists a rotated refresh token before returning the new session", async () => {
    mocks.loadCredentials.mockResolvedValue({
      ...CREDENTIALS,
      clientId: CONFIG.cognitoClientId,
    });
    mocks.refreshAccessToken.mockResolvedValue({
      access_token: "new-access",
      id_token: "new-identity",
      refresh_token: "rotated-refresh",
      expires_in: 3600,
    });

    const manager = new AuthManager(CONFIG);
    const [accessToken, identityToken] = await Promise.all([
      manager.getAccessToken(),
      manager.getIdentityToken(),
    ]);

    expect([accessToken, identityToken]).toEqual(["new-access", "new-identity"]);
    expect(mocks.refreshAccessToken).toHaveBeenCalledOnce();
    expect(mocks.saveCredentials).toHaveBeenCalledWith(
      CONFIG.credentialsPath,
      expect.objectContaining({ refreshToken: "rotated-refresh" }),
    );
  });

  it("refreshes a server-rejected access token and coalesces concurrent rejection recovery", async () => {
    mocks.loadCredentials.mockResolvedValue({
      ...CREDENTIALS,
      clientId: CONFIG.cognitoClientId,
    });
    mocks.refreshAccessToken
      .mockResolvedValueOnce({
        access_token: "rejected-access",
        id_token: "identity-one",
        expires_in: 3600,
      })
      .mockResolvedValueOnce({
        access_token: "replacement-access",
        id_token: "identity-two",
        expires_in: 3600,
      });

    const manager = new AuthManager(CONFIG);
    const rejected = await manager.getAccessToken();
    const replacements = await Promise.all([
      manager.refreshRejectedAccessToken(rejected),
      manager.refreshRejectedAccessToken(rejected),
    ]);

    expect(rejected).toBe("rejected-access");
    expect(replacements).toEqual(["replacement-access", "replacement-access"]);
    expect(mocks.refreshAccessToken).toHaveBeenCalledTimes(2);
  });

  it("refuses to mint a token once a logout is in progress (NEW-004 entry guard)", async () => {
    mocks.loadCredentials.mockResolvedValue({ ...CREDENTIALS, clientId: CONFIG.cognitoClientId });
    let releaseRevoke!: () => void;
    mocks.revokeRefreshToken.mockImplementation(
      () => new Promise<void>((resolve) => (releaseRevoke = resolve)),
    );

    const manager = new AuthManager(CONFIG);
    const loggingOut = manager.logout(); // raises logoutInProgress, then awaits revoke
    await expect(manager.getAccessToken()).rejects.toBeInstanceOf(NotLoggedInError);
    releaseRevoke();
    await loggingOut;
  });
});
