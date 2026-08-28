import { homedir } from "node:os";
import { join, resolve, win32 as win32Path } from "node:path";
import { z } from "zod";

/**
 * The public package defaults to Audix's production services and public native
 * PKCE client. Environment overrides remain available for local development
 * and automated testing.
 */
/** Require HTTPS except for explicit localhost development. */
const httpsUnlessLocalhost = (value: string): boolean => {
  const url = new URL(value);
  const isLocalhost = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  return url.protocol === "https:" || isLocalhost;
};

const isLoopbackRedirect = (value: string): boolean => {
  const url = new URL(value);
  return (
    url.protocol === "http:" &&
    url.hostname === "127.0.0.1" &&
    url.port !== "" &&
    url.pathname === "/auth/callback" &&
    url.username === "" &&
    url.password === "" &&
    url.search === "" &&
    url.hash === ""
  );
};

const usesOnlyMcpScopes = (value: string): boolean => {
  const scopes = value.split(/\s+/).filter(Boolean);
  const allowed = new Set(["openid", "email", "aws.cognito.signin.user.admin"]);
  return (
    scopes.includes("openid") &&
    scopes.includes("email") &&
    scopes.every((scope) => allowed.has(scope))
  );
};

const configSchema = z.object({
  apiBaseUrl: z
    .url()
    .refine(httpsUnlessLocalhost, "must be https (http is allowed only for localhost)"),
  cognitoDomain: z
    .url()
    .refine(httpsUnlessLocalhost, "must be https (http is allowed only for localhost)"),
  cognitoClientId: z.string().min(1),
  appSyncGraphqlEndpoint: z
    .url()
    .refine(httpsUnlessLocalhost, "must be https (http is allowed only for localhost)"),
  awsRegion: z.string().min(1),
  redirectUri: z
    .url()
    .refine(isLoopbackRedirect, "must be an explicit 127.0.0.1 /auth/callback URL with a port"),
  oauthScopes: z.string().min(1).refine(usesOnlyMcpScopes, "contains an unsupported OAuth scope"),
  credentialsPath: z.string().min(1),
  projectRoot: z.string().min(1).optional(),
  // Expected HTTPS origin of every presigned S3 upload and download URL.
  uploadBucketOrigin: z
    .url()
    .refine((value) => new URL(value).protocol === "https:", "must be https"),
});

export type Config = z.infer<typeof configSchema>;

function windowsLocalAppData(env: NodeJS.ProcessEnv, userHome: string): string {
  return env["LOCALAPPDATA"] ?? win32Path.join(userHome, "AppData", "Local");
}

export function assertWindowsCredentialsPath(
  credentialsPath: string,
  env: NodeJS.ProcessEnv = process.env,
  userHome: string = homedir(),
): void {
  const privateRoot = win32Path.resolve(windowsLocalAppData(env, userHome));
  const candidate = win32Path.resolve(credentialsPath);
  const relative = win32Path.relative(privateRoot, candidate);
  if (relative === "" || relative.startsWith("..\\") || win32Path.isAbsolute(relative)) {
    throw new Error(
      `On Windows, AUDIX_CREDENTIALS_PATH must be a file under the current user's LOCALAPPDATA directory (${privateRoot}).`,
    );
  }
}

export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  userHome: string = homedir(),
): Config {
  const credentialsPath =
    env["AUDIX_CREDENTIALS_PATH"] ??
    (platform === "win32"
      ? win32Path.join(windowsLocalAppData(env, userHome), "Audix", "credentials.json")
      : join(userHome, ".audix", "credentials.json"));
  if (platform === "win32") assertWindowsCredentialsPath(credentialsPath, env, userHome);

  const configuredProjectRoot = env["AUDIX_PROJECT_ROOT"] ?? env["CLAUDE_PROJECT_DIR"];
  return configSchema.parse({
    apiBaseUrl: env["AUDIX_API_URL"] ?? "https://api.audix.ai/audix-api",
    cognitoDomain: env["AUDIX_COGNITO_DOMAIN"] ?? "https://auth.audix.ai",
    cognitoClientId: env["AUDIX_COGNITO_CLIENT_ID"] ?? "2lev18pt5uv5f7cabo1ihicnae",
    appSyncGraphqlEndpoint:
      env["AUDIX_APPSYNC_GRAPHQL_ENDPOINT"] ?? "https://graphql.api.audix.ai/graphql",
    awsRegion: env["AUDIX_AWS_REGION"] ?? "us-east-1",
    redirectUri: env["AUDIX_REDIRECT_URI"] ?? "http://127.0.0.1:49673/auth/callback",
    oauthScopes:
      env["AUDIX_OAUTH_SCOPES"] ?? "openid email aws.cognito.signin.user.admin",
    credentialsPath,
    // Claude Code supplies CLAUDE_PROJECT_DIR for the advertised one-line
    // install. Other clients can set AUDIX_PROJECT_ROOT or expose MCP roots.
    ...(configuredProjectRoot === undefined
      ? {}
      : { projectRoot: resolve(configuredProjectRoot) }),
    // Presigned URLs use the global S3 endpoint form (no region segment).
    uploadBucketOrigin:
      env["AUDIX_UPLOAD_BUCKET_ORIGIN"] ?? "https://code-target-bucket-prod.s3.amazonaws.com",
  });
}
