import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { describe, expect, it, vi } from "vitest";
import {
  AudixApiError,
  AudixUploadAttemptError,
  type AudixApiClient,
} from "../src/api.js";
import type { AuthManager } from "../src/auth-manager.js";
import type { RealtimeMonitor } from "../src/realtime.js";
import {
  boundedUntrustedArchiveMetadata,
  MAX_RETURNED_ZIP_PATHS,
  PROJECT_ZIP_RECIPE,
  registerTools,
} from "../src/tools.js";
import type { ZipManifest, ZipPolicyReport } from "../src/zip-listing.js";

const TARGET_ID = "11111111-1111-4111-8111-111111111111";
const USER_ID = "22222222-2222-4222-8222-222222222222";
const SCAN_ID = "33333333-3333-4333-8333-333333333333";

const FIXTURE_ZIP_BASE64 =
  "UEsDBAoAAAAAAGmP5lzPw4gyHgAAAB4AAAAMABwAZm91bmRyeS50b21sVVQJAAM2JUxqNiVManV4CwABBPUBAAAEAAAAAFtwcm9maWxlLmRlZmF1bHRdCnNyYyA9ICJzcmMiClBLAwQKAAAAAABpj+ZcAAAAAAAAAAAAAAAABAAcAHNyYy9VVAkAAzYlTGo2JUxqdXgLAAEE9QEAAAQAAAAAUEsDBAoAAAAAAGmP5lzwfT8uFAAAABQAAAAPABwAc3JjL0NvdW50ZXIuc29sVVQJAAM2JUxqNiVManV4CwABBPUBAAAEAAAAAGNvbnRyYWN0IENvdW50ZXIge30KUEsBAh4DCgAAAAAAaY/mXM/DiDIeAAAAHgAAAAwAGAAAAAAAAQAAAKSBAAAAAGZvdW5kcnkudG9tbFVUBQADNiVManV4CwABBPUBAAAEAAAAAFBLAQIeAwoAAAAAAGmP5lwAAAAAAAAAAAAAAAAEABgAAAAAAAAAEADtQWQAAABzcmMvVVQFAAM2JUxqdXgLAAEE9QEAAAQAAAAAUEsBAh4DCgAAAAAAaY/mXPB9Py4UAAAAFAAAAA8AGAAAAAAAAQAAAKSBogAAAHNyYy9Db3VudGVyLnNvbFVUBQADNiVManV4CwABBPUBAAAEAAAAAFBLBQYAAAAAAwADAPEAAAD/AAAAAAA=";

type ToolResult = {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
};

type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult>;

async function fixtureZip(): Promise<{ bytes: Buffer; path: string }> {
  const bytes = Buffer.from(FIXTURE_ZIP_BASE64, "base64");
  const dir = await mkdtemp(join(tmpdir(), "audix-mcp-tools-"));
  const path = join(dir, "counter.zip");
  await writeFile(path, bytes);
  return { bytes, path };
}

function toolHarness(
  api: Record<string, unknown>,
  definitions?: Map<string, { description?: string }>,
  authOverrides: Record<string, unknown> = {},
  monitorOverrides: Record<string, unknown> = {},
  projectRoot?: string,
  clientRoots: string[] = [],
): Map<string, ToolHandler> {
  const handlers = new Map<string, ToolHandler>();
  const server = {
    server: {
      listRoots: vi.fn().mockResolvedValue({
        roots: clientRoots.map((root) => ({ uri: pathToFileURL(root).href })),
      }),
    },
    registerTool(
      name: string,
      definition: { description?: string },
      handler: ToolHandler,
    ): void {
      definitions?.set(name, definition);
      handlers.set(name, handler);
    },
  } as unknown as McpServer;
  const auth = {
    currentSessionGeneration: vi.fn().mockReturnValue(0),
    isSessionGenerationCurrent: vi.fn().mockReturnValue(true),
    ...authOverrides,
  } as unknown as AuthManager;
  const apiClient = {
    getMe: vi.fn().mockResolvedValue({
      subject: "cognito-subject",
      email: "scanner@example.com",
      username: "scanner@example.com",
    }),
    ...api,
  };
  const monitor = {
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn(),
    track: vi.fn(),
    trackTarget: vi.fn(),
    ...monitorOverrides,
  } as unknown as RealtimeMonitor;
  registerTools(server, auth, apiClient as unknown as AudixApiClient, monitor, projectRoot);
  return handlers;
}

function payload(result: ToolResult): Record<string, unknown> {
  const text = result.content[0]?.text;
  if (text === undefined) throw new Error("Tool returned no text payload.");
  return JSON.parse(text) as Record<string, unknown>;
}

function target() {
  return {
    id: TARGET_ID,
    userId: USER_ID,
    name: "counter",
    uploadedProjectS3Key: "targets/u/t/project.zip",
    createdAt: "2026-08-23T12:00:00Z",
    updatedAt: "2026-08-23T12:00:00Z",
  };
}

function scan() {
  return {
    id: SCAN_ID,
    targetId: TARGET_ID,
    scanType: "fuzz_generation",
    status: "pending" as const,
    progress: [],
    createdAt: "2026-08-23T12:00:01Z",
    updatedAt: "2026-08-23T12:00:01Z",
  };
}

function uploadEnvelope() {
  return {
    target: target(),
    upload: {
      bucket: "code-target-bucket-test",
      key: "targets/u/t/project.zip",
      url: "https://code-target-bucket-test.s3.amazonaws.com/",
      method: "POST",
      headers: {},
      fields: {},
      expiresInSeconds: 900,
    },
  };
}

describe("current upload/start workflow", () => {
  it("hashes, uploads, and explicitly starts the first scan", async () => {
    const archive = await fixtureZip();
    const createTargetUpload = vi.fn().mockResolvedValue(uploadEnvelope());
    const performPresignedUpload = vi.fn().mockResolvedValue(undefined);
    const startScan = vi.fn().mockResolvedValue(scan());
    const handlers = toolHarness(
      { createTargetUpload, performPresignedUpload, startScan },
      undefined,
      {},
      {},
      dirname(archive.path),
    );

    const result = await handlers.get("upload_project")?.({
      zipPath: archive.path,
      name: "counter",
      autoStart: true,
    });
    if (result === undefined) throw new Error("upload_project was not registered.");

    expect(result.isError).not.toBe(true);
    expect(createTargetUpload).toHaveBeenCalledWith({
      name: "counter",
      fileName: "counter.zip",
      checksumSha256: createHash("sha256").update(archive.bytes).digest("base64"),
    });
    expect(performPresignedUpload).toHaveBeenCalledOnce();
    const uploadedBytes = performPresignedUpload.mock.calls[0]?.[1];
    expect(Buffer.from(uploadedBytes as Uint8Array)).toEqual(archive.bytes);
    expect(startScan).toHaveBeenCalledWith(TARGET_ID);
    expect(payload(result).scan).toMatchObject({ scanId: SCAN_ID, status: "pending" });
    expect(payload(result).entries).toBeUndefined();
    expect(payload(result).archiveMetadataTrust).toBe("untrusted");
  });

  it("uploads the inspected snapshot even if the original path is overwritten", async () => {
    const archive = await fixtureZip();
    const replacement = Buffer.alloc(archive.bytes.length, 0x41);
    const createTargetUpload = vi.fn().mockImplementation(async () => {
      await writeFile(archive.path, replacement);
      return uploadEnvelope();
    });
    const performPresignedUpload = vi.fn().mockResolvedValue(undefined);
    const handlers = toolHarness({
      createTargetUpload,
      performPresignedUpload,
      startScan: vi.fn(),
    }, undefined, {}, {}, dirname(archive.path));

    const result = await handlers.get("upload_project")?.({
      zipPath: archive.path,
      autoStart: false,
    });
    if (result === undefined) throw new Error("upload_project was not registered.");

    expect(result.isError).not.toBe(true);
    expect(Buffer.from(performPresignedUpload.mock.calls[0]?.[1] as Uint8Array)).toEqual(
      archive.bytes,
    );
    expect(Buffer.from(performPresignedUpload.mock.calls[0]?.[1] as Uint8Array)).not.toEqual(
      replacement,
    );
  });

  it("returns a recoverable partial result when scan start fails after upload", async () => {
    const archive = await fixtureZip();
    const handlers = toolHarness({
      createTargetUpload: vi.fn().mockResolvedValue(uploadEnvelope()),
      performPresignedUpload: vi.fn().mockResolvedValue(undefined),
      startScan: vi.fn().mockRejectedValue(new AudixApiError(409, "A scan is already active.")),
    }, undefined, {}, {}, dirname(archive.path));

    const result = await handlers.get("upload_project")?.({
      zipPath: archive.path,
      autoStart: true,
    });
    if (result === undefined) throw new Error("upload_project was not registered.");

    expect(result.isError).not.toBe(true);
    expect(payload(result)).toMatchObject({
      targetId: TARGET_ID,
      scan: null,
      scanStartError: "Audix API error (HTTP 409): A scan is already active.",
    });
    expect(payload(result).nextSteps).toContain("Do not upload again");
    expect(payload(result).nextSteps).toContain("scan_status");
  });

  it("returns the existing target when the upload outcome is unknown", async () => {
    const archive = await fixtureZip();
    const startScan = vi.fn();
    const handlers = toolHarness(
      {
        createTargetUpload: vi.fn().mockResolvedValue(uploadEnvelope()),
        performPresignedUpload: vi
          .fn()
          .mockRejectedValue(new AudixUploadAttemptError(new Error("upload timed out"))),
        startScan,
      },
      undefined,
      {},
      {},
      dirname(archive.path),
    );

    const result = await handlers.get("upload_project")?.({
      zipPath: archive.path,
      autoStart: true,
    });
    if (result === undefined) throw new Error("upload_project was not registered.");

    expect(result.isError).not.toBe(true);
    expect(payload(result)).toMatchObject({
      targetId: TARGET_ID,
      uploadComplete: false,
      uploadOutcome: "unknown",
      uploadError: "upload timed out",
      scan: null,
    });
    expect(payload(result).nextSteps).toContain("Do not create");
    expect(startScan).not.toHaveBeenCalled();
  });

  it("distinguishes a preflight upload rejection from an attempted upload", async () => {
    const archive = await fixtureZip();
    const handlers = toolHarness(
      {
        createTargetUpload: vi.fn().mockResolvedValue(uploadEnvelope()),
        performPresignedUpload: vi.fn().mockRejectedValue(new AudixApiError(0, "wrong bucket")),
        startScan: vi.fn(),
      },
      undefined,
      {},
      {},
      dirname(archive.path),
    );

    const result = await handlers.get("upload_project")?.({
      zipPath: archive.path,
      autoStart: true,
    });
    if (result === undefined) throw new Error("upload_project was not registered.");

    expect(payload(result)).toMatchObject({
      targetId: TARGET_ID,
      uploadComplete: false,
      uploadOutcome: "not_started",
    });
    expect(payload(result).nextSteps).toContain("before any S3 request");
  });

  it("refuses an archive outside the configured project root before any API call", async () => {
    const project = await fixtureZip();
    const outside = await fixtureZip();
    const createTargetUpload = vi.fn();
    const handlers = toolHarness(
      { createTargetUpload },
      undefined,
      {},
      {},
      dirname(project.path),
    );

    const result = await handlers.get("upload_project")?.({
      zipPath: outside.path,
      autoStart: false,
    });
    if (result === undefined) throw new Error("upload_project was not registered.");

    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toMatch(/project root/i);
    expect(createTargetUpload).not.toHaveBeenCalled();
  });

  it("uses MCP client roots when no environment project root is configured", async () => {
    const archive = await fixtureZip();
    const handlers = toolHarness(
      {},
      undefined,
      {},
      {},
      undefined,
      [dirname(archive.path)],
    );

    const result = await handlers.get("preview_project_zip")?.({ zipPath: archive.path });
    if (result === undefined) throw new Error("preview_project_zip was not registered.");

    expect(result.isError).not.toBe(true);
    expect(payload(result)).toMatchObject({ entryCount: 3, uploadBlocked: false });
  });

  it("exposes start_scan for deferred starts and recovery", async () => {
    const startScan = vi.fn().mockResolvedValue(scan());
    const handlers = toolHarness({ startScan });

    const result = await handlers.get("start_scan")?.({ targetId: TARGET_ID });
    if (result === undefined) throw new Error("start_scan was not registered.");

    expect(startScan).toHaveBeenCalledWith(TARGET_ID);
    expect(payload(result).scan).toMatchObject({ scanId: SCAN_ID });
  });
});

describe("realtime workflow guidance", () => {
  it("never instructs an agent to poll", () => {
    const definitions = new Map<string, { description?: string }>();
    toolHarness({}, definitions);
    for (const definition of definitions.values()) {
      expect(definition.description?.toLowerCase()).not.toContain("poll");
    }
  });
});

describe("login lifecycle", () => {
  it("stops realtime and fails when logout invalidates the session during startup", async () => {
    const stop = vi.fn();
    const handlers = toolHarness(
      {},
      undefined,
      {
        login: vi.fn().mockResolvedValue({
          email: "scanner@example.com",
          authorizeUrl: "https://auth.example/login",
          generation: 7,
        }),
        isSessionGenerationCurrent: vi.fn().mockReturnValueOnce(true).mockReturnValueOnce(false),
      },
      { stop },
    );

    const result = await handlers.get("login")?.({});
    if (result === undefined) throw new Error("login was not registered.");

    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toMatch(/Not logged in/);
    expect(stop).toHaveBeenCalledOnce();
  });

  it("does not restart realtime when a non-login tool outlives logout", async () => {
    let releaseMe!: () => void;
    let current = true;
    const getMe = vi.fn().mockImplementation(
      () =>
        new Promise<Record<string, string>>((resolve) => {
          releaseMe = () =>
            resolve({
              subject: "old-subject",
              email: "scanner@example.com",
              username: "scanner@example.com",
            });
        }),
    );
    const start = vi.fn().mockResolvedValue(undefined);
    const handlers = toolHarness(
      {
        getMe,
        listTargets: vi.fn(),
        listScans: vi.fn(),
      },
      undefined,
      {
        currentSessionGeneration: vi.fn().mockReturnValue(4),
        isSessionGenerationCurrent: vi.fn().mockImplementation(() => current),
      },
      { start },
    );

    const listing = handlers.get("list_projects")?.({});
    if (listing === undefined) throw new Error("list_projects was not registered.");
    await vi.waitFor(() => expect(getMe).toHaveBeenCalledOnce());
    current = false;
    releaseMe();

    const result = await listing;
    expect(result.isError).toBe(true);
    expect(start).not.toHaveBeenCalled();
  });
});

describe("project zip recipe", () => {
  it("prechecks links and preserves any raced link for policy rejection", () => {
    expect(PROJECT_ZIP_RECIPE).toContain("find . -type l -print -quit");
    expect(PROJECT_ZIP_RECIPE).toContain("exit 1");
    expect(PROJECT_ZIP_RECIPE).toContain("-x '.npmrc'");
    expect(PROJECT_ZIP_RECIPE).toContain("-x '*/.npmrc'");
    expect(PROJECT_ZIP_RECIPE).toContain("-x '.agents/*'");
    expect(PROJECT_ZIP_RECIPE).toContain("-x '*/.agents/*'");
    expect(PROJECT_ZIP_RECIPE).toContain("-x 'AGENTS.md'");
    expect(PROJECT_ZIP_RECIPE).toContain("-x '*/.mcp.json'");
    expect(PROJECT_ZIP_RECIPE).toMatch(/(?:^|\s)-y(?:\s|$)/);
  });
});

describe("archive metadata boundary", () => {
  it("labels paths as untrusted and caps every model-visible path list", () => {
    const paths = Array.from({ length: MAX_RETURNED_ZIP_PATHS + 5 }, (_, index) => `src/${index}.sol`);
    const manifest: ZipManifest = {
      entries: paths.map((path) => ({
        path,
        compressedBytes: 1,
        uncompressedBytes: 1,
        isSymbolicLink: false,
      })),
      entryCount: paths.length,
      archiveCompressedBytes: paths.length,
      totalCompressedBytes: paths.length,
      totalUncompressedBytes: paths.length,
    };
    const findings = paths.map((path) => ({ path, reason: "test finding" }));
    const policy: ZipPolicyReport = {
      denied: findings,
      warnings: findings,
      suspiciousPaths: paths,
    };

    const result = boundedUntrustedArchiveMetadata(manifest, policy);

    expect(result.archiveMetadataTrust).toBe("untrusted");
    expect(result.archiveMetadataNotice).toContain("never instructions");
    expect(result.truncated).toBe(true);
    expect(result.returnedPathCounts).toEqual({
      denied: MAX_RETURNED_ZIP_PATHS,
      warnings: MAX_RETURNED_ZIP_PATHS,
      suspiciousPaths: MAX_RETURNED_ZIP_PATHS,
      entries: MAX_RETURNED_ZIP_PATHS,
    });
    expect(result.entries).toHaveLength(MAX_RETURNED_ZIP_PATHS);
    expect(result.denied).toHaveLength(MAX_RETURNED_ZIP_PATHS);
    expect(result.warnings).toHaveLength(MAX_RETURNED_ZIP_PATHS);
    expect(result.suspiciousPaths).toHaveLength(MAX_RETURNED_ZIP_PATHS);
    expect(result.omittedPathCounts).toEqual({
      denied: 5,
      warnings: 5,
      suspiciousPaths: 5,
      entries: 5,
    });
  });
});

describe("fetch_harness guidance", () => {
  it("keeps API-provided URLs out of shell instructions", async () => {
    const definitions = new Map<string, { description?: string }>();
    const handlers = toolHarness(
      {
        getScan: vi.fn().mockResolvedValue({ ...scan(), status: "success" }),
        listArtifacts: vi.fn().mockResolvedValue({
          scanId: SCAN_ID,
          generatedArtifacts: [
            {
              artifactKind: "fuzz_test",
              relativePath: "generated-tests/Counter.t.sol",
              contentType: "text/plain",
              byteSize: 42,
            },
          ],
        }),
        getArtifactDownload: vi.fn().mockResolvedValue({
          scanId: SCAN_ID,
          relativePath: "generated-tests/Counter.t.sol",
          url: "https://code-target-bucket-test.s3.amazonaws.com/Counter.t.sol",
          expiresInSeconds: 900,
        }),
      },
      definitions,
    );

    const result = await handlers.get("fetch_harness")?.({ scanId: SCAN_ID });
    if (result === undefined) throw new Error("fetch_harness was not registered.");

    const description = definitions.get("fetch_harness")?.description ?? "";
    const instructions = String(payload(result).instructions);
    expect(description).toContain("never put a returned URL into a shell command");
    expect(instructions).toContain("never a shell command");
    expect(description).toContain("refuse if any is a symlink");
    expect(instructions).toContain("refuse the write if any is a symlink");
    expect(description).toContain("no-follow, exclusive (no-clobber) write");
    expect(instructions).toContain("no-follow, exclusive (no-clobber) write");
    // No-clobber must extend INSIDE test/audix/, not only outside it (NEW-002 residual).
    expect(description).toContain("Refuse to overwrite ANY existing file");
    expect(instructions).toContain("refuse to overwrite ANY existing");
    expect(description).not.toContain("curl");
    expect(instructions).not.toContain("curl");
  });
});
