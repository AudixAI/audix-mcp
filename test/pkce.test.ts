import { describe, expect, it } from "vitest";
import { buildAuthorizeUrl, challengeFor, createPkcePair, createState } from "../src/pkce.js";

describe("challengeFor", () => {
  it("matches the RFC 7636 appendix B vector", () => {
    expect(challengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
  });
});

describe("createPkcePair", () => {
  it("produces a base64url verifier whose challenge round-trips", () => {
    const pair = createPkcePair();
    expect(pair.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(challengeFor(pair.verifier)).toBe(pair.challenge);
  });

  it("produces distinct verifiers", () => {
    expect(createPkcePair().verifier).not.toBe(createPkcePair().verifier);
    expect(createState()).not.toBe(createState());
  });
});

describe("buildAuthorizeUrl", () => {
  it("carries all required Cognito authorize params", () => {
    const url = new URL(
      buildAuthorizeUrl({
        cognitoDomain: "https://auth.example.com",
        clientId: "client123",
        redirectUri: "http://localhost:3000/auth/callback",
        scopes: "openid email",
        state: "st4te",
        challenge: "ch4llenge",
      }),
    );
    expect(url.origin).toBe("https://auth.example.com");
    expect(url.pathname).toBe("/oauth2/authorize");
    expect(url.searchParams.get("client_id")).toBe("client123");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid email");
    expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:3000/auth/callback");
    expect(url.searchParams.get("state")).toBe("st4te");
    expect(url.searchParams.get("code_challenge")).toBe("ch4llenge");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });
});
