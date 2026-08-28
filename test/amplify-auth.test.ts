import { Amplify } from "aws-amplify";
import { fetchAuthSession } from "aws-amplify/auth";
import { describe, expect, it, vi } from "vitest";
import { createUserPoolTokenProvider } from "../src/realtime.js";

const ACCESS_TOKEN =
  "eyJhbGciOiJSUzI1NiJ9." +
  "eyJzdWIiOiJjb2duaXRvLXN1YmplY3QiLCJ0b2tlbl91c2UiOiJhY2Nlc3MifQ." +
  "signature";

describe("Amplify Cognito token provider", () => {
  it("makes the MCP-managed access token available to the pinned userPool auth path", async () => {
    const getAccessToken = vi.fn().mockResolvedValue(ACCESS_TOKEN);
    Amplify.configure(
      {},
      { Auth: { tokenProvider: createUserPoolTokenProvider(getAccessToken) } },
    );

    const session = await fetchAuthSession();

    expect(session.tokens?.accessToken.toString()).toBe(ACCESS_TOKEN);
    expect(session.tokens?.accessToken.payload).toMatchObject({
      sub: "cognito-subject",
      token_use: "access",
    });
    expect(getAccessToken).toHaveBeenCalledOnce();
  });
});
