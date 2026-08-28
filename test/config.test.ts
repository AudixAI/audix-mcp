import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

describe("loadConfig", () => {
  it("defaults to the public production services", () => {
    const config = loadConfig({});
    expect(config.apiBaseUrl).toBe("https://api.audix.ai/audix-api");
    expect(config.cognitoDomain).toBe("https://auth.audix.ai");
    expect(config.cognitoClientId).toBe("2lev18pt5uv5f7cabo1ihicnae");
    expect(config.appSyncGraphqlEndpoint).toBe("https://graphql.api.audix.ai/graphql");
    expect(config.awsRegion).toBe("us-east-1");
    expect(config.redirectUri).toBe("http://127.0.0.1:49673/auth/callback");
    expect(config.oauthScopes).toContain("aws.cognito.signin.user.admin");
    expect(config.credentialsPath).toMatch(/\.audix\/credentials\.json$/);
    expect(config.projectRoot).toBeUndefined();
    expect(config.uploadBucketOrigin).toBe(
      "https://code-target-bucket-prod.s3.amazonaws.com",
    );
  });

  it("honors environment overrides", () => {
    const config = loadConfig({
      AUDIX_API_URL: "http://localhost:8000",
      AUDIX_COGNITO_CLIENT_ID: "other-client",
      AUDIX_APPSYNC_GRAPHQL_ENDPOINT: "https://graphql.example.com/graphql",
      AUDIX_AWS_REGION: "us-west-2",
      AUDIX_CREDENTIALS_PATH: "/tmp/creds.json",
      AUDIX_PROJECT_ROOT: "/tmp/audix-project",
      AUDIX_UPLOAD_BUCKET_ORIGIN: "https://other-bucket.s3.amazonaws.com",
    });
    expect(config.apiBaseUrl).toBe("http://localhost:8000");
    expect(config.cognitoClientId).toBe("other-client");
    expect(config.appSyncGraphqlEndpoint).toBe("https://graphql.example.com/graphql");
    expect(config.awsRegion).toBe("us-west-2");
    expect(config.credentialsPath).toBe("/tmp/creds.json");
    expect(config.projectRoot).toBe("/tmp/audix-project");
    expect(config.uploadBucketOrigin).toBe("https://other-bucket.s3.amazonaws.com");
  });

  it("uses Claude Code's injected project directory without extra configuration", () => {
    expect(
      loadConfig({
        AUDIX_COGNITO_CLIENT_ID: "mcp-client",
        CLAUDE_PROJECT_DIR: "/tmp/claude-project",
      }).projectRoot,
    ).toBe("/tmp/claude-project");
  });

  it("rejects a non-URL api base loudly", () => {
    expect(() =>
      loadConfig({ AUDIX_API_URL: "not a url", AUDIX_COGNITO_CLIENT_ID: "mcp-client" }),
    ).toThrow();
  });

  it("allows http only for localhost (mirrors the UI env rule)", () => {
    const client = { AUDIX_COGNITO_CLIENT_ID: "mcp-client" };
    expect(() => loadConfig({ ...client, AUDIX_API_URL: "http://localhost:8000" })).not.toThrow();
    expect(() => loadConfig({ ...client, AUDIX_API_URL: "http://127.0.0.1:8000" })).not.toThrow();
    expect(() => loadConfig({ ...client, AUDIX_API_URL: "http://api.example.com" })).toThrow(/https/);
    expect(() => loadConfig({ ...client, AUDIX_COGNITO_DOMAIN: "http://auth.example.com" })).toThrow(/https/);
  });

  it("requires https for the presigned bucket origin, even localhost", () => {
    expect(() => loadConfig({ AUDIX_COGNITO_CLIENT_ID: "mcp-client", AUDIX_UPLOAD_BUCKET_ORIGIN: "http://localhost:9000" })).toThrow(
      /https/,
    );
  });

  it("rejects non-loopback redirects and broader OAuth scopes", () => {
    const client = { AUDIX_COGNITO_CLIENT_ID: "mcp-client" };
    expect(() =>
      loadConfig({ ...client, AUDIX_REDIRECT_URI: "http://localhost:49673/auth/callback" }),
    ).toThrow(/127\.0\.0\.1/);
    expect(() =>
      loadConfig({ ...client, AUDIX_OAUTH_SCOPES: "openid email profile" }),
    ).toThrow(/unsupported OAuth scope/);
  });

  it("uses per-user LocalAppData storage on Windows", () => {
    const config = loadConfig(
      {
        LOCALAPPDATA: String.raw`C:\Users\alice\AppData\Local`,
        AUDIX_COGNITO_CLIENT_ID: "mcp-client",
      },
      "win32",
      String.raw`C:\Users\alice`,
    );
    expect(config.credentialsPath).toBe(
      String.raw`C:\Users\alice\AppData\Local\Audix\credentials.json`,
    );
  });

  it("rejects Windows credential overrides outside LocalAppData", () => {
    expect(() =>
      loadConfig(
        {
          LOCALAPPDATA: String.raw`C:\Users\alice\AppData\Local`,
          AUDIX_COGNITO_CLIENT_ID: "mcp-client",
          AUDIX_CREDENTIALS_PATH: String.raw`C:\shared\credentials.json`,
        },
        "win32",
        String.raw`C:\Users\alice`,
      ),
    ).toThrow(/LOCALAPPDATA/);
  });
});
