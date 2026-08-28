import { spawn } from "node:child_process";
import { win32 as win32Path } from "node:path";
import type { Config } from "./config.js";
import {
  exchangeCodeForTokens,
  readJwtClaim,
  refreshAccessToken,
  revokeRefreshToken,
  waitForAuthorizationCode,
} from "./oauth.js";
import { buildAuthorizeUrl, createPkcePair, createState } from "./pkce.js";
import { deleteCredentials, loadCredentials, saveCredentials } from "./token-store.js";

const LOGIN_TIMEOUT_MS = 300_000;
/** Refresh a minute early so a token never expires mid-request. */
const EXPIRY_SLACK_MS = 60_000;
/**
 * Same 5-minute reuse cap the UI BFF puts on cached access tokens: bounds how
 * long a minted token keeps riding the cache. (Locally the exposure is
 * smaller — single user, in-memory — but the bar is same-or-stronger.)
 */
const MAX_CACHE_REUSE_MS = 5 * 60_000;

export function accessTokenCacheTtlMs(expiresInSeconds: number): number {
  return Math.max(0, Math.min(expiresInSeconds * 1000 - EXPIRY_SLACK_MS, MAX_CACHE_REUSE_MS));
}

type BrowserOpener = (url: string) => Promise<unknown>;

export function browserLaunchSpec(
  url: string,
  platform: NodeJS.Platform = process.platform,
  windowsDirectory: string =
    process.env["SystemRoot"] ?? process.env["WINDIR"] ?? String.raw`C:\Windows`,
): { file: string; arguments: [string] } {
  const file =
    platform === "darwin"
      ? "/usr/bin/open"
      : platform === "win32"
        ? win32Path.join(windowsDirectory, "explorer.exe")
        : "/usr/bin/xdg-open";
  return { file, arguments: [url] };
}

async function openWithSystemHandler(url: string): Promise<unknown> {
  const launch = browserLaunchSpec(url);
  // Built-in spawn, shell:false, absolute platform binary, URL as one arg —
  // the shell never sees the URL, so its `&`/metacharacters can't be parsed
  // as commands (the MCP-001 fix). No third-party opener dependency: this is
  // a thin bridge and every shipped dep is attack surface on the user's box.
  const child = spawn(launch.file, launch.arguments, {
    shell: false,
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  });
  child.on("error", () => {
    // Non-fatal: the URL is also reported to the user via the login tool.
  });
  child.unref();
  return child;
}

/** Pass the URL as one opaque value to the platform browser integration. */
export function openBrowser(url: string, opener: BrowserOpener = openWithSystemHandler): void {
  void opener(url).catch(() => {
    // Non-fatal: the URL is also reported to the user via the login tool.
  });
}

export class NotLoggedInError extends Error {
  override readonly name = "NotLoggedInError";
  constructor() {
    super("Not logged in. Run the `login` tool first.");
  }
}

/**
 * Owns the credential lifecycle. The refresh token lives in a 0600 file; the
 * access and identity tokens live only in this process's memory and are never
 * included in tool results.
 */
export class AuthManager {
  private accessToken: string | undefined;
  private identityToken: string | undefined;
  private sessionExpiresAt = 0;
  private refreshInFlight: Promise<void> | undefined;
  /**
   * Serializes every credential lifecycle transition. The MCP SDK dispatches
   * tool calls on independent promise chains, so login, logout, and refresh
   * must not persist or delete credentials concurrently.
   */
  private authLifecycleTail: Promise<void> = Promise.resolve();
  private authGeneration = 0;
  private logoutInProgress = false;

  constructor(
    private readonly config: Config,
    private readonly launchBrowser: (url: string) => void = openBrowser,
  ) {}

  /** Interactive PKCE login via the system browser. Returns the email only. */
  async login(): Promise<{ email: string; authorizeUrl: string; generation: number }> {
    const generation = this.authGeneration;
    const pkce = createPkcePair();
    const state = createState();
    const authorizeUrl = buildAuthorizeUrl({
      cognitoDomain: this.config.cognitoDomain,
      clientId: this.config.cognitoClientId,
      redirectUri: this.config.redirectUri,
      scopes: this.config.oauthScopes,
      state,
      challenge: pkce.challenge,
    });

    const codePromise = waitForAuthorizationCode({
      redirectUri: this.config.redirectUri,
      expectedState: state,
      timeoutMs: LOGIN_TIMEOUT_MS,
    });
    console.error(`[audix-mcp] Opening browser for login: ${authorizeUrl}`);
    this.launchBrowser(authorizeUrl);
    const code = await codePromise;

    const tokens = await exchangeCodeForTokens({
      cognitoDomain: this.config.cognitoDomain,
      clientId: this.config.cognitoClientId,
      redirectUri: this.config.redirectUri,
      code,
      verifier: pkce.verifier,
    });
    if (tokens.refresh_token === undefined) {
      throw new Error("Cognito did not return a refresh token; cannot persist the session.");
    }
    const refreshToken = tokens.refresh_token;
    const email =
      (tokens.id_token !== undefined ? readJwtClaim(tokens.id_token, "email") : undefined) ??
      "unknown";

    return this.withAuthLifecycleLock(async () => {
      this.assertAuthGeneration(generation);
      await saveCredentials(this.config.credentialsPath, {
        refreshToken,
        clientId: this.config.cognitoClientId,
        email,
        obtainedAt: new Date().toISOString(),
      });
      this.assertAuthGeneration(generation);
      this.cacheTokens(tokens.access_token, tokens.id_token, tokens.expires_in);
      return { email, authorizeUrl, generation };
    });
  }

  isSessionGenerationCurrent(generation: number): boolean {
    return !this.logoutInProgress && this.authGeneration === generation;
  }

  currentSessionGeneration(): number {
    return this.authGeneration;
  }

  async logout(): Promise<void> {
    // Bump the generation and raise the flag SYNCHRONOUSLY, before any await,
    // so a concurrent getAccessToken() cannot mint-and-cache across the logout.
    this.authGeneration += 1;
    this.logoutInProgress = true;
    this.accessToken = undefined;
    this.identityToken = undefined;
    this.sessionExpiresAt = 0;

    const generation = this.authGeneration;
    return this.withAuthLifecycleLock(async () => {
      try {
        await this.performLogout();
      } finally {
        // A newer queued logout owns the barrier until it completes.
        if (this.authGeneration === generation) this.logoutInProgress = false;
      }
    });
  }

  private async performLogout(): Promise<void> {
    let revocationError: unknown;
    try {
      const credentials = await loadCredentials(this.config.credentialsPath);
      if (credentials !== undefined) {
        await revokeRefreshToken({
          cognitoDomain: this.config.cognitoDomain,
          clientId: credentials.clientId,
          refreshToken: credentials.refreshToken,
        });
      }
    } catch (error) {
      revocationError = error;
    }

    let deletionError: unknown;
    try {
      await deleteCredentials(this.config.credentialsPath);
    } catch (error) {
      deletionError = error;
    }

    if (revocationError !== undefined && deletionError !== undefined) {
      throw new AggregateError(
        [revocationError, deletionError],
        "Logout failed: refresh-token revocation and local credential deletion both failed.",
      );
    }
    if (deletionError !== undefined) {
      throw new Error(`Failed to clear local credentials: ${(deletionError as Error).message}`);
    }
    if (revocationError !== undefined) {
      throw new Error(
        `Local credentials were cleared, but refresh-token revocation failed: ` +
          `${(revocationError as Error).message}`,
      );
    }
  }

  async currentEmail(): Promise<string | undefined> {
    return (await loadCredentials(this.config.credentialsPath))?.email;
  }

  /** Mints (or reuses) an access token from the stored refresh token. */
  async getAccessToken(): Promise<string> {
    if (this.logoutInProgress) throw new NotLoggedInError();
    if (this.accessToken !== undefined && Date.now() < this.sessionExpiresAt) {
      return this.accessToken;
    }
    await this.refreshSession();
    if (this.accessToken === undefined) {
      throw new Error("Cognito refresh did not return an access token.");
    }
    return this.accessToken;
  }

  /**
   * Replace an access token that the API has explicitly rejected. The rejected
   * token is part of the call so concurrent 401 responses coalesce: if another
   * request already refreshed it, reuse that newer token instead of rotating
   * the session again.
   */
  async refreshRejectedAccessToken(rejectedToken: string): Promise<string> {
    if (this.logoutInProgress) throw new NotLoggedInError();
    if (
      this.accessToken !== undefined &&
      this.accessToken !== rejectedToken &&
      Date.now() < this.sessionExpiresAt
    ) {
      return this.accessToken;
    }
    if (this.accessToken === rejectedToken) this.accessToken = undefined;
    await this.refreshSession();
    if (this.accessToken === undefined) {
      throw new Error("Cognito refresh did not return an access token.");
    }
    return this.accessToken;
  }

  /** Returns an in-memory ID token for the user-bound AppSync subscription. */
  async getIdentityToken(): Promise<string> {
    if (this.logoutInProgress) throw new NotLoggedInError();
    if (this.identityToken !== undefined && Date.now() < this.sessionExpiresAt) {
      return this.identityToken;
    }
    await this.refreshSession();
    if (this.identityToken === undefined) {
      throw new Error("Cognito refresh did not return an identity token. Run `login` again.");
    }
    return this.identityToken;
  }

  private async refreshSession(): Promise<void> {
    if (this.refreshInFlight !== undefined) {
      await this.refreshInFlight;
      return;
    }
    const operation = this.withAuthLifecycleLock(() => this.performRefresh());
    this.refreshInFlight = operation;
    try {
      await operation;
    } finally {
      if (this.refreshInFlight === operation) this.refreshInFlight = undefined;
    }
  }

  private async performRefresh(): Promise<void> {
    // Snapshot the generation before the refresh await; if a logout intervenes
    // (bumping it or raising the flag) the minted token is dropped, never cached.
    const generation = this.authGeneration;
    const credentials = await loadCredentials(this.config.credentialsPath);
    if (credentials === undefined) throw new NotLoggedInError();
    if (credentials.clientId !== this.config.cognitoClientId) {
      throw new Error(
        "Stored credentials were issued for a different Cognito client. Run `login` again.",
      );
    }
    let tokens;
    try {
      tokens = await refreshAccessToken({
        cognitoDomain: this.config.cognitoDomain,
        clientId: this.config.cognitoClientId,
        refreshToken: credentials.refreshToken,
      });
    } catch (error) {
      throw new Error(
        `Session refresh failed (${(error as Error).message}). Run \`login\` again.`,
      );
    }
    if (this.logoutInProgress || this.authGeneration !== generation) {
      // A logout overlapped this refresh: do not cache or return the token.
      throw new NotLoggedInError();
    }
    if (tokens.refresh_token !== undefined) {
      await saveCredentials(this.config.credentialsPath, {
        ...credentials,
        refreshToken: tokens.refresh_token,
        obtainedAt: new Date().toISOString(),
      });
    }
    if (this.logoutInProgress || this.authGeneration !== generation) {
      throw new NotLoggedInError();
    }
    this.cacheTokens(tokens.access_token, tokens.id_token, tokens.expires_in);
  }

  private assertAuthGeneration(generation: number): void {
    if (this.logoutInProgress || this.authGeneration !== generation) {
      throw new NotLoggedInError();
    }
  }

  private withAuthLifecycleLock<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.authLifecycleTail;
    let release!: () => void;
    this.authLifecycleTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    return (async () => {
      await previous;
      try {
        return await operation();
      } finally {
        release();
      }
    })();
  }

  private cacheTokens(
    accessToken: string,
    identityToken: string | undefined,
    expiresInSeconds: number,
  ): void {
    this.accessToken = accessToken;
    this.identityToken = identityToken;
    this.sessionExpiresAt = Date.now() + accessTokenCacheTtlMs(expiresInSeconds);
  }
}
