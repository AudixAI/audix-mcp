import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AudixApiClient,
  assertAllowedPresignedUrl,
  assertAllowedUploadHeaders,
  bucketFromOrigin,
  harnessRepoPath,
  isSafeRelativePath,
  MAX_API_RESPONSE_BYTES,
  MAX_ARTIFACT_RELATIVE_PATH_LENGTH,
  MAX_GENERATED_ARTIFACTS,
  newestScanForTarget,
  scanWireSchema,
  targetWireSchema,
  uploadZipToPresignedPost,
  type ScanWire,
} from "../src/api.js";
import { accessTokenCacheTtlMs } from "../src/auth-manager.js";

const TARGET_A = "11111111-1111-4111-8111-111111111111";
const TARGET_B = "22222222-2222-4222-8222-222222222222";

function scan(id: string, targetId: string, createdAt: string): ScanWire {
  return {
    id,
    targetId,
    scanType: "fuzz_generation",
    status: "pending",
    progress: [],
    createdAt,
    updatedAt: createdAt,
  };
}

describe("newestScanForTarget", () => {
  const older = scan("99999999-9999-4999-8999-999999999999", TARGET_A, "2026-07-06T10:00:00Z");
  const newer = scan("55555555-5555-4555-8555-555555555555", TARGET_A, "2026-07-06T12:00:00Z");
  const tieLow = scan("33333333-3333-4333-8333-333333333333", TARGET_A, "2026-07-06T12:00:00Z");
  const otherTarget = scan("44444444-4444-4444-8444-444444444444", TARGET_B, "2026-07-06T13:00:00Z");

  it("is order-free and picks newest createdAt", () => {
    for (const scans of [
      [older, newer, otherTarget],
      [otherTarget, newer, older],
      [newer, otherTarget, older],
    ]) {
      expect(newestScanForTarget(scans, TARGET_A)?.id).toBe(newer.id);
    }
  });

  it("breaks createdAt ties by lowest id", () => {
    expect(newestScanForTarget([newer, tieLow], TARGET_A)?.id).toBe(tieLow.id);
    expect(newestScanForTarget([tieLow, newer], TARGET_A)?.id).toBe(tieLow.id);
  });

  it("returns undefined when the target has no scans", () => {
    expect(newestScanForTarget([otherTarget], TARGET_A)).toBeUndefined();
  });
});

describe("isSafeRelativePath", () => {
  it.each(["generated-tests/Counter.t.sol", "generated-tests/sub/dir/F.t.sol", "manifest.json"])(
    "accepts %s",
    (path) => expect(isSafeRelativePath(path)).toBe(true),
  );

  it.each([
    "/absolute.sol",
    "../up.sol",
    "a/../b.sol",
    "a/./b.sol",
    "a//b.sol",
    "space in name.sol",
    "semi;colon.sol",
    "",
  ])("rejects %s", (path) => expect(isSafeRelativePath(path)).toBe(false));
});

describe("harnessRepoPath", () => {
  it("maps generated-tests/<p> to test/audix/<p>", () => {
    expect(harnessRepoPath("generated-tests/Counter.t.sol")).toBe("test/audix/Counter.t.sol");
    expect(harnessRepoPath("generated-tests/deep/nested/F.t.sol")).toBe(
      "test/audix/deep/nested/F.t.sol",
    );
  });

  it.each([
    "manifest.json", // no prefix — not a harness file to write
    ".github/workflows/pwn.yml", // API-controlled path escaping the harness dir
    "generated-tests/../../etc/passwd", // traversal under the prefix
    "/generated-tests/abs.sol", // absolute
    "generated-tests/../evil.sol",
    "generated-tests/", // prefix only, empty tail is still safe-relative? guard anyway
  ])("refuses to map %s (returns undefined)", (path) => {
    expect(harnessRepoPath(path)).toBeUndefined();
  });
});

describe("assertAllowedPresignedUrl (mirror of the UI #271 check)", () => {
  const ORIGIN = "https://code-target-bucket-test.s3.amazonaws.com";

  it("accepts an https URL on the expected origin", () => {
    expect(() =>
      assertAllowedPresignedUrl(`${ORIGIN}/key?X-Amz-Signature=abc`, "upload", ORIGIN),
    ).not.toThrow();
  });

  it("accepts a realistic multi-parameter S3 SigV4 presign (the `&`-chained query)", () => {
    const presign =
      `${ORIGIN}/targets/abc/harness.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256` +
      `&X-Amz-Credential=AKIAEXAMPLE%2F20260824%2Fus-east-1%2Fs3%2Faws4_request` +
      `&X-Amz-Date=20260824T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host` +
      `&X-Amz-Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`;
    expect(() =>
      assertAllowedPresignedUrl(presign, "download", ORIGIN),
    ).not.toThrow();
  });

  it.each([
    ["apostrophe and substitution", `${ORIGIN}/key'$(touch%20marker)`],
    ["whitespace", `${ORIGIN}/key value`],
    ["backslash", `${ORIGIN}/key\\evil`],
    ["semicolon", `${ORIGIN}/key;id`],
    ["pipe", `${ORIGIN}/key|id`],
    ["backtick", `${ORIGIN}/key\`id\``],
  ])("rejects a same-origin URL containing %s", (_label, url) => {
    expect(() => assertAllowedPresignedUrl(url, "download", ORIGIN)).toThrow(
      /unsafe characters/,
    );
  });

  it.each([
    ["http scheme", "http://code-target-bucket-test.s3.amazonaws.com/key"],
    ["other bucket", "https://evil-bucket.s3.amazonaws.com/key"],
    ["regional-endpoint mismatch", "https://code-target-bucket-test.s3.us-east-1.amazonaws.com/key"],
    ["other port", "https://code-target-bucket-test.s3.amazonaws.com:8443/key"],
    ["subdomain trick", "https://code-target-bucket-test.s3.amazonaws.com.evil.com/key"],
  ])("rejects %s", (_label, url) => {
    expect(() => assertAllowedPresignedUrl(url, "download", ORIGIN)).toThrow(/Presigned/);
  });
});

describe("bucketFromOrigin", () => {
  it("reads the bucket label from a virtual-hosted origin (global + regional)", () => {
    expect(bucketFromOrigin("https://code-target-bucket-test.s3.amazonaws.com")).toBe(
      "code-target-bucket-test",
    );
    expect(bucketFromOrigin("https://code-target-bucket-test.s3.us-east-1.amazonaws.com")).toBe(
      "code-target-bucket-test",
    );
  });
});

describe("accessTokenCacheTtlMs", () => {
  it("caps reuse at 5 minutes like the UI BFF", () => {
    expect(accessTokenCacheTtlMs(3600)).toBe(5 * 60_000);
  });

  it("respects shorter token lifetimes minus slack", () => {
    expect(accessTokenCacheTtlMs(120)).toBe(60_000);
    expect(accessTokenCacheTtlMs(30)).toBe(0);
  });
});

describe("wire schemas", () => {
  it("parses a target payload with microsecond ISO timestamps", () => {
    const target = targetWireSchema.parse({
      id: TARGET_A,
      userId: TARGET_B,
      name: "counter",
      uploadedProjectS3Key: "targets/u/t/project.zip",
      createdAt: "2026-07-06T12:00:00.123456Z",
      updatedAt: "2026-07-06T12:00:00.123456Z",
    });
    expect(target.uploadedProjectS3Key).toBe("targets/u/t/project.zip");
  });

  it("rejects unknown scan statuses loudly", () => {
    expect(() =>
      scanWireSchema.parse({
        ...scan(TARGET_A, TARGET_B, "2026-07-06T12:00:00Z"),
        status: "exploded",
      }),
    ).toThrow();
  });
});

describe("paginated list contracts", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function apiClient(): AudixApiClient {
    return new AudixApiClient(
      "https://api.example",
      "https://bucket.s3.amazonaws.com",
      {
        getAccessToken: async () => "access-token",
        refreshRejectedAccessToken: async () => "refreshed-access-token",
      },
    );
  }

  it("unwraps the first target page without changing the MCP tool contract", async () => {
    const expectedTarget = {
      id: TARGET_A,
      userId: TARGET_B,
      name: "counter",
      uploadedProjectS3Key: "targets/u/t/project.zip",
      createdAt: "2026-08-23T12:00:00Z",
      updatedAt: "2026-08-23T12:00:00Z",
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        targets: [expectedTarget],
        nextCursor: "opaque-next-page",
      }),
    );

    await expect(apiClient().listTargets()).resolves.toEqual([expectedTarget]);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "https://api.example/api/v1/targets?limit=100",
    );
  });

  it("unwraps scans and forwards a target filter for authoritative status lookup", async () => {
    const expectedScan = scan(
      "33333333-3333-4333-8333-333333333333",
      TARGET_A,
      "2026-08-23T12:00:01Z",
    );
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        scans: [{ ...expectedScan, targetName: "counter" }],
        nextCursor: null,
      }),
    );

    await expect(apiClient().listScans(TARGET_A)).resolves.toEqual([expectedScan]);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      `https://api.example/api/v1/scans?limit=100&targetId=${TARGET_A}`,
    );
  });
});

describe("createTargetUpload", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sends the checksum contract without removed validation/auto-start fields", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          target: {
            id: TARGET_A,
            userId: TARGET_B,
            name: "counter",
            uploadedProjectS3Key: "targets/u/t/project.zip",
            createdAt: "2026-08-23T12:00:00Z",
            updatedAt: "2026-08-23T12:00:00Z",
          },
          upload: {
            bucket: "code-target-bucket-test",
            key: "targets/u/t/project.zip",
            url: "https://code-target-bucket-test.s3.amazonaws.com/",
            method: "POST",
            headers: {},
            fields: {},
            expiresInSeconds: 900,
          },
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      ),
    );
    const api = new AudixApiClient(
      "https://api.example.com/audix-api",
      "https://code-target-bucket-test.s3.amazonaws.com",
      {
        getAccessToken: async () => "access-token",
        refreshRejectedAccessToken: async () => "refreshed-access-token",
      },
    );

    await api.createTargetUpload({
      name: "counter",
      fileName: "counter.zip",
      checksumSha256: "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=",
    });

    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(JSON.parse(String(init?.body))).toEqual({
      name: "counter",
      fileName: "counter.zip",
      contentType: "application/zip",
      checksumSha256: "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=",
    });
  });
});

describe("authenticated request recovery", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("refreshes once after a 401 and retries with the replacement token", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ detail: "expired" }), { status: 401 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ subject: "user", email: "dev@example.com", username: null }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      );
    const accessTokens = {
      getAccessToken: vi.fn().mockResolvedValue("stale-token"),
      refreshRejectedAccessToken: vi.fn().mockResolvedValue("fresh-token"),
    };
    const api = new AudixApiClient(
      "https://api.example",
      "https://bucket.s3.amazonaws.com",
      accessTokens,
    );

    await expect(api.getMe()).resolves.toMatchObject({ subject: "user" });
    expect(accessTokens.refreshRejectedAccessToken).toHaveBeenCalledOnce();
    expect(accessTokens.refreshRejectedAccessToken).toHaveBeenCalledWith("stale-token");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.map(([, init]) => init?.headers)).toEqual([
      expect.objectContaining({ authorization: "Bearer stale-token" }),
      expect.objectContaining({ authorization: "Bearer fresh-token" }),
    ]);
  });

  it("stops after one refresh when the replacement token is also rejected", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ detail: "unauthorized" }), { status: 401 }),
      );
    const accessTokens = {
      getAccessToken: vi.fn().mockResolvedValue("stale-token"),
      refreshRejectedAccessToken: vi.fn().mockResolvedValue("fresh-token"),
    };
    const api = new AudixApiClient(
      "https://api.example",
      "https://bucket.s3.amazonaws.com",
      accessTokens,
    );

    await expect(api.getMe()).rejects.toMatchObject({ status: 401 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(accessTokens.refreshRejectedAccessToken).toHaveBeenCalledOnce();
  });

  it("does not refresh or retry non-authentication failures", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ detail: "unavailable" }), { status: 503 }));
    const accessTokens = {
      getAccessToken: vi.fn().mockResolvedValue("access-token"),
      refreshRejectedAccessToken: vi.fn(),
    };
    const api = new AudixApiClient(
      "https://api.example",
      "https://bucket.s3.amazonaws.com",
      accessTokens,
    );

    await expect(api.getMe()).rejects.toMatchObject({ status: 503 });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(accessTokens.refreshRejectedAccessToken).not.toHaveBeenCalled();
  });
});

describe("artifact response boundaries", () => {
  const SCAN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const OTHER_SCAN_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

  afterEach(() => vi.restoreAllMocks());

  function apiClient(): AudixApiClient {
    return new AudixApiClient(
      "https://api.example",
      "https://bucket.s3.amazonaws.com",
      {
        getAccessToken: async () => "access-token",
        refreshRejectedAccessToken: async () => "refreshed-access-token",
      },
    );
  }

  const artifact = (relativePath: string) => ({
    artifactKind: "fuzz_test",
    relativePath,
    contentType: "text/plain",
    byteSize: 42,
  });

  it("accepts a bounded artifact manifest and binds it to the requested scan", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        scanId: SCAN_ID,
        generatedArtifacts: [artifact("generated-tests/Counter.t.sol")],
      }),
    );

    await expect(apiClient().listArtifacts(SCAN_ID)).resolves.toMatchObject({ scanId: SCAN_ID });
  });

  it("rejects a mismatched scan identity, duplicate paths, and excessive cardinality", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    fetchMock.mockResolvedValueOnce(
      Response.json({ scanId: OTHER_SCAN_ID, generatedArtifacts: [] }),
    );
    await expect(apiClient().listArtifacts(SCAN_ID)).rejects.toThrow(/identity/i);

    fetchMock.mockResolvedValueOnce(
      Response.json({
        scanId: SCAN_ID,
        generatedArtifacts: [
          artifact("generated-tests/Duplicate.t.sol"),
          artifact("generated-tests/duplicate.t.sol"),
        ],
      }),
    );
    await expect(apiClient().listArtifacts(SCAN_ID)).rejects.toThrow(/duplicate/i);

    fetchMock.mockResolvedValueOnce(
      Response.json({
        scanId: SCAN_ID,
        generatedArtifacts: Array.from({ length: MAX_GENERATED_ARTIFACTS + 1 }, (_, index) =>
          artifact(`generated-tests/${index}.t.sol`),
        ),
      }),
    );
    await expect(apiClient().listArtifacts(SCAN_ID)).rejects.toThrow();
  });

  it("rejects overlong paths and API bodies before downstream fanout", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      Response.json({
        scanId: SCAN_ID,
        generatedArtifacts: [artifact(`generated-tests/${"a".repeat(MAX_ARTIFACT_RELATIVE_PATH_LENGTH)}.sol`)],
      }),
    );
    await expect(apiClient().listArtifacts(SCAN_ID)).rejects.toThrow();

    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ padding: "x".repeat(MAX_API_RESPONSE_BYTES) }), {
        headers: { "content-type": "application/json" },
      }),
    );
    await expect(apiClient().listArtifacts(SCAN_ID)).rejects.toThrow(/exceeds/i);
  });

  it("binds a download response to the exact requested scan and path", async () => {
    const path = "generated-tests/Counter.t.sol";
    const fetchMock = vi.spyOn(globalThis, "fetch");
    fetchMock.mockResolvedValueOnce(
      Response.json({
        scanId: SCAN_ID,
        relativePath: path,
        url: "https://bucket.s3.amazonaws.com/Counter.t.sol",
        expiresInSeconds: 900,
      }),
    );
    await expect(apiClient().getArtifactDownload(SCAN_ID, path)).resolves.toMatchObject({
      relativePath: path,
    });

    fetchMock.mockResolvedValueOnce(
      Response.json({
        scanId: OTHER_SCAN_ID,
        relativePath: path,
        url: "https://bucket.s3.amazonaws.com/Counter.t.sol",
        expiresInSeconds: 900,
      }),
    );
    await expect(apiClient().getArtifactDownload(SCAN_ID, path)).rejects.toThrow(/identity/i);

    fetchMock.mockResolvedValueOnce(
      Response.json({
        scanId: SCAN_ID,
        relativePath: "generated-tests/Other.t.sol",
        url: "https://bucket.s3.amazonaws.com/Counter.t.sol",
        expiresInSeconds: 900,
      }),
    );
    await expect(apiClient().getArtifactDownload(SCAN_ID, path)).rejects.toThrow(/identity/i);
  });

  it("treats UUID hex casing as the same scan identity", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ scanId: SCAN_ID.toLowerCase(), generatedArtifacts: [] }),
    );
    await expect(apiClient().listArtifacts(SCAN_ID.toUpperCase())).resolves.toMatchObject({
      scanId: SCAN_ID,
    });
  });
});

describe("presigned upload headers", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    "Host",
    "Authorization",
    "Cookie",
    "Proxy-Authorization",
    "Connection",
    "Content-Length",
    "Transfer-Encoding",
  ])("explicitly rejects the %s header", (name) => {
    expect(() => assertAllowedUploadHeaders({ [name]: "attacker-controlled" })).toThrow(
      /forbidden/,
    );
  });

  it("rejects unrecognized headers because the deployed allowlist is empty", () => {
    expect(() => assertAllowedUploadHeaders({ "x-amz-meta-future": "value" })).toThrow(
      /allows none/,
    );
  });

  it("sends no envelope headers for the current empty-header contract", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));

    await uploadZipToPresignedPost(
      {
        bucket: "code-target-bucket-test",
        key: "targets/u/t/project.zip",
        url: "https://code-target-bucket-test.s3.amazonaws.com/",
        method: "POST",
        headers: {},
        fields: {},
        expiresInSeconds: 900,
      },
      new TextEncoder().encode("zip bytes"),
      "project.zip",
    );

    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(init?.headers).toBeUndefined();
    expect(init?.redirect).toBe("manual");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("aborts a stalled upload at the configured deadline", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      }),
    );

    await expect(
      uploadZipToPresignedPost(
        {
          bucket: "code-target-bucket-test",
          key: "targets/u/t/project.zip",
          url: "https://code-target-bucket-test.s3.amazonaws.com/",
          method: "POST",
          headers: {},
          fields: {},
          expiresInSeconds: 900,
        },
        new TextEncoder().encode("zip bytes"),
        "project.zip",
        1,
      ),
    ).rejects.toBeDefined();
  });
});
