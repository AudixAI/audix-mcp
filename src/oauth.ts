import { createServer } from "node:http";
import { z } from "zod";

export const OAUTH_REQUEST_TIMEOUT_MS = 30_000;
export const MAX_OAUTH_RESPONSE_BYTES = 65_536;

const tokenResponseSchema = z.object({
  access_token: z.string().min(1),
  id_token: z.string().min(1).optional(),
  refresh_token: z.string().min(1).optional(),
  expires_in: z.number().int().positive(),
  token_type: z.literal("Bearer"),
});

export type TokenResponse = z.infer<typeof tokenResponseSchema>;

async function parseBoundedOAuthJson(response: Response): Promise<unknown> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_OAUTH_RESPONSE_BYTES) {
    await response.body?.cancel();
    throw new Error(`OAuth response exceeds ${MAX_OAUTH_RESPONSE_BYTES} bytes.`);
  }
  if (response.body === null) return JSON.parse("");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_OAUTH_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error(`OAuth response exceeds ${MAX_OAUTH_RESPONSE_BYTES} bytes.`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function postTokenEndpoint(
  cognitoDomain: string,
  form: Record<string, string>,
  timeoutMs: number,
): Promise<TokenResponse> {
  const response = await fetch(new URL("/oauth2/token", cognitoDomain), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const body: unknown = await parseBoundedOAuthJson(response).catch((error) => {
    if (error instanceof Error && error.message.includes("exceeds")) throw error;
    return undefined;
  });
  if (!response.ok) {
    const detail =
      typeof body === "object" && body !== null && "error" in body
        ? String((body as { error: unknown }).error)
        : `HTTP ${response.status}`;
    throw new Error(`Cognito token endpoint rejected the request: ${detail}`);
  }
  return tokenResponseSchema.parse(body);
}

export async function exchangeCodeForTokens(options: {
  cognitoDomain: string;
  clientId: string;
  redirectUri: string;
  code: string;
  verifier: string;
  requestTimeoutMs?: number;
}): Promise<TokenResponse> {
  return postTokenEndpoint(options.cognitoDomain, {
    grant_type: "authorization_code",
    client_id: options.clientId,
    code: options.code,
    redirect_uri: options.redirectUri,
    code_verifier: options.verifier,
  }, options.requestTimeoutMs ?? OAUTH_REQUEST_TIMEOUT_MS);
}

export async function refreshAccessToken(options: {
  cognitoDomain: string;
  clientId: string;
  refreshToken: string;
  requestTimeoutMs?: number;
}): Promise<TokenResponse> {
  return postTokenEndpoint(options.cognitoDomain, {
    grant_type: "refresh_token",
    client_id: options.clientId,
    refresh_token: options.refreshToken,
  }, options.requestTimeoutMs ?? OAUTH_REQUEST_TIMEOUT_MS);
}

export async function revokeRefreshToken(options: {
  cognitoDomain: string;
  clientId: string;
  refreshToken: string;
  requestTimeoutMs?: number;
}): Promise<void> {
  const response = await fetch(new URL("/oauth2/revoke", options.cognitoDomain), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      token: options.refreshToken,
      client_id: options.clientId,
    }).toString(),
    redirect: "manual",
    signal: AbortSignal.timeout(options.requestTimeoutMs ?? OAUTH_REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`Cognito revocation endpoint rejected the request: HTTP ${response.status}`);
  }
}

/** Minimal JWT payload read (no signature verification — display only). */
export function readJwtClaim(token: string, claim: string): string | undefined {
  const payload = token.split(".")[1];
  if (payload === undefined) return undefined;
  try {
    const claims: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (typeof claims !== "object" || claims === null) return undefined;
    const value = (claims as Record<string, unknown>)[claim];
    return typeof value === "string" ? value : undefined;
  } catch {
    return undefined;
  }
}

const CALLBACK_PAGE = `<!doctype html><html><body style="font-family: system-ui; padding: 3rem">
<h2>Audix login complete</h2><p>You can close this tab and return to your agent.</p>
</body></html>`;

/**
 * One-shot loopback listener for the OAuth redirect. Binds 127.0.0.1 on the
 * port declared in the registered redirect URI and resolves with the ?code once
 * a request with the expected state arrives.
 */
export async function waitForAuthorizationCode(options: {
  redirectUri: string;
  expectedState: string;
  timeoutMs: number;
}, serverFactory: typeof createServer = createServer): Promise<string> {
  const redirect = new URL(options.redirectUri);
  const port = Number(redirect.port !== "" ? redirect.port : 80);

  return await new Promise<string>((resolve, reject) => {
    const server = serverFactory((request, response) => {
      let url: URL;
      try {
        url = new URL(request.url ?? "/", options.redirectUri);
      } catch {
        // A malformed request must not crash a pending login.
        response.writeHead(404).end();
        return;
      }
      if (url.pathname !== redirect.pathname) {
        response.writeHead(404).end();
        return;
      }
      // Validate state BEFORE acting on the callback. Any local process can
      // hit this port, so a request that doesn't carry the exact state we
      // issued (whether a spoofed error or a stray probe) must NOT be able to
      // resolve or poison the pending login — 404 it and keep listening. Only
      // the real Cognito redirect (which echoes our state) or the timeout
      // ends the wait.
      const state = url.searchParams.get("state");
      if (state !== options.expectedState) {
        response.writeHead(404).end();
        return;
      }
      const finish = (fn: () => void) => {
        response.writeHead(200, { "content-type": "text/html" }).end(CALLBACK_PAGE, () => {
          server.close();
          clearTimeout(timer);
          fn();
        });
      };
      const error = url.searchParams.get("error");
      if (error !== null) {
        const description = url.searchParams.get("error_description") ?? "";
        finish(() => reject(new Error(`Login failed: ${error} ${description}`.trim())));
        return;
      }
      const code = url.searchParams.get("code");
      if (code === null) {
        finish(() => reject(new Error("Login failed: callback carried the state but no code.")));
        return;
      }
      finish(() => resolve(code));
    });

    const timer = setTimeout(() => {
      server.close();
      reject(new Error(`Login timed out after ${Math.round(options.timeoutMs / 1000)}s.`));
    }, options.timeoutMs);

    server.on("error", (err) => {
      clearTimeout(timer);
      const hint =
        (err as NodeJS.ErrnoException).code === "EADDRINUSE"
          ? ` Port ${port} is in use (a local dev server?). Stop it and retry — the registered OAuth callback pins this port.`
          : "";
      reject(new Error(`Could not start the login listener on port ${port}: ${err.message}.${hint}`));
    });

    server.listen(port, "127.0.0.1");
  });
}
