import { z } from "zod";

/** Wire schemas for the public API surfaces used by this server. */

export const MAX_API_RESPONSE_BYTES = 1_048_576;
export const MAX_GENERATED_ARTIFACTS = 20;
export const MAX_ARTIFACT_RELATIVE_PATH_LENGTH = 512;
export const MAX_PRESIGNED_URL_LENGTH = 4_096;
export const MAX_S3_ERROR_BODY_BYTES = 8_192;
export const API_REQUEST_TIMEOUT_MS = 30_000;
export const S3_UPLOAD_TIMEOUT_MS = 5 * 60_000;

export const targetWireSchema = z.object({
  id: z.uuid(),
  userId: z.uuid(),
  name: z.string(),
  uploadedProjectS3Key: z.string().min(1),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
export type TargetWire = z.infer<typeof targetWireSchema>;

const pageCursorSchema = z.string().min(1).max(512);

const targetsPageResponseSchema = z.object({
  targets: z.array(targetWireSchema),
  nextCursor: pageCursorSchema.nullable(),
});

export const scanStatusSchema = z.enum([
  "pending",
  "running",
  "rerunning",
  "success",
  "failed",
  "cancelled",
]);

export const scanProgressStageSchema = z.enum([
  "analyzing_contracts",
  "building_test_environment",
  "modeling_state",
  "defining_properties",
  "generating_targets",
  "verifying_harness",
  "finalizing_results",
]);

export const scanProgressEventSchema = z.strictObject({
  recordedAt: z.iso.datetime(),
  stage: scanProgressStageSchema,
});

export const scanWireSchema = z.object({
  id: z.uuid(),
  targetId: z.uuid(),
  scanType: z.string(),
  status: scanStatusSchema,
  progress: z.array(scanProgressEventSchema).default([]),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
export type ScanWire = z.infer<typeof scanWireSchema>;

const scansPageResponseSchema = z.object({
  scans: z.array(scanWireSchema),
  nextCursor: pageCursorSchema.nullable(),
});

const presignedUploadSchema = z.object({
  bucket: z.string().min(1),
  key: z.string().min(1),
  url: z.url(),
  method: z.string(),
  headers: z.record(z.string(), z.string()),
  fields: z.record(z.string(), z.string()),
  expiresInSeconds: z.number().int().positive(),
});

const targetUploadResponseSchema = z.object({
  target: targetWireSchema,
  upload: presignedUploadSchema,
});
export type TargetUploadResponse = z.infer<typeof targetUploadResponseSchema>;

export const generatedArtifactSchema = z.object({
  artifactKind: z.string().min(1).max(100),
  relativePath: z.string().min(1).max(MAX_ARTIFACT_RELATIVE_PATH_LENGTH),
  contentType: z.string().max(200).nullable(),
  byteSize: z.number().int().nonnegative(),
});

const scanArtifactsResponseSchema = z.object({
  scanId: z.uuid(),
  generatedArtifacts: z.array(generatedArtifactSchema).max(MAX_GENERATED_ARTIFACTS),
});
export type ScanArtifactsResponse = z.infer<typeof scanArtifactsResponseSchema>;

const artifactDownloadResponseSchema = z.object({
  scanId: z.uuid(),
  relativePath: z.string().min(1).max(MAX_ARTIFACT_RELATIVE_PATH_LENGTH),
  url: z.url().max(MAX_PRESIGNED_URL_LENGTH),
  expiresInSeconds: z.number().int().positive(),
});
export type ArtifactDownloadResponse = z.infer<typeof artifactDownloadResponseSchema>;

const authMeResponseSchema = z.object({
  subject: z.string(),
  email: z.string().nullable(),
  username: z.string().nullable(),
});
export type AuthMeResponse = z.infer<typeof authMeResponseSchema>;

/** Client-side relative-path validation before paths reach the agent. */
export function isSafeRelativePath(relativePath: string): boolean {
  if (!/^[A-Za-z0-9._/-]+$/.test(relativePath)) return false;
  if (relativePath.startsWith("/")) return false;
  const segments = relativePath.split("/");
  return segments.every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

export class AudixApiError extends Error {
  override readonly name = "AudixApiError";
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** The S3 request was started, so a transport failure leaves its outcome unknown. */
export class AudixUploadAttemptError extends Error {
  override readonly name = "AudixUploadAttemptError";
  constructor(readonly original: unknown) {
    super(original instanceof Error ? original.message : String(original));
  }
}

export interface AccessTokenProvider {
  getAccessToken(): Promise<string>;
  refreshRejectedAccessToken(rejectedToken: string): Promise<string>;
}

async function readBoundedText(
  response: Response,
  maxBytes: number = MAX_API_RESPONSE_BYTES,
): Promise<string> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await response.body?.cancel();
    throw new AudixApiError(0, `Network response exceeds ${maxBytes} bytes.`);
  }

  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new AudixApiError(0, `Network response exceeds ${maxBytes} bytes.`);
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
  return new TextDecoder().decode(bytes);
}

async function parseBoundedJson(response: Response): Promise<unknown> {
  return JSON.parse(await readBoundedText(response));
}

async function parseErrorDetail(response: Response): Promise<string> {
  const body: unknown = await parseBoundedJson(response).catch(() => undefined);
  if (typeof body === "object" && body !== null && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    return JSON.stringify(detail);
  }
  return `HTTP ${response.status}`;
}

/** Every presigned S3 URL must be HTTPS and match the configured origin. */
// `&` is required — every real S3 SigV4 presign chains its X-Amz-* query
// params with it. It is safe here because these URLs are never rendered into a
// shell command (fetch_harness hands them to the agent's download tool as
// opaque values); the genuinely dangerous characters — quotes, backtick, `$`,
// `;`, `|`, `<`, `>`, parens, whitespace, newlines, backslash — stay rejected.
const SAFE_PRESIGNED_URL_CHARACTERS = /^[A-Za-z0-9._~:/?#%+=,&-]+$/;

export function assertAllowedPresignedUrl(
  url: string,
  kind: "upload" | "download",
  expectedOrigin: string,
): void {
  // Validate the API-provided string before URL parsing can normalize it. AWS
  // presigns percent-encode characters outside this deliberately small set;
  // raw shell metacharacters, quotes, whitespace, and backslashes are never
  // accepted at the API-to-agent boundary.
  if (!SAFE_PRESIGNED_URL_CHARACTERS.test(url)) {
    throw new Error(`Presigned ${kind} URL contains unsafe characters.`);
  }
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`Presigned ${kind} URL has a non-https scheme: ${parsed.protocol}`);
  }
  if (parsed.origin !== expectedOrigin) {
    throw new Error(`Presigned ${kind} URL origin is not allowed: ${parsed.origin}`);
  }
}

/**
 * Bucket name encoded in a virtual-hosted S3 origin
 * (https://<bucket>.s3[.<region>].amazonaws.com) — the leftmost host label.
 */
export function bucketFromOrigin(origin: string): string {
  const host = new URL(origin).hostname;
  const label = host.split(".")[0];
  if (label === undefined || label === "") {
    throw new Error(`Cannot derive a bucket name from origin: ${origin}`);
  }
  return label;
}

export class AudixApiClient {
  constructor(
    private readonly baseUrl: string,
    private readonly presignedUrlOrigin: string,
    private readonly accessTokens: AccessTokenProvider,
  ) {}

  private async request<T>(schema: z.ZodType<T>, path: string, init?: RequestInit): Promise<T> {
    const send = async (token: string): Promise<Response> =>
      fetch(`${this.baseUrl}/api/v1${path}`, {
        ...init,
        // The live UI enforces the same bounded presign posture.
        signal: init?.signal ?? AbortSignal.timeout(API_REQUEST_TIMEOUT_MS),
        headers: {
          accept: "application/json",
          authorization: `Bearer ${token}`,
          ...(init?.body !== undefined ? { "content-type": "application/json" } : {}),
        },
      });

    let token = await this.accessTokens.getAccessToken();
    let response = await send(token);
    if (response.status === 401) {
      await response.body?.cancel();
      token = await this.accessTokens.refreshRejectedAccessToken(token);
      response = await send(token);
    }
    if (!response.ok) {
      throw new AudixApiError(response.status, await parseErrorDetail(response));
    }
    return schema.parse(await parseBoundedJson(response));
  }

  async getMe(): Promise<AuthMeResponse> {
    return this.request(authMeResponseSchema, "/auth/me");
  }

  async listTargets(): Promise<TargetWire[]> {
    const page = await this.request(targetsPageResponseSchema, "/targets?limit=100");
    return page.targets;
  }

  async getTarget(targetId: string): Promise<TargetWire> {
    return this.request(targetWireSchema, `/targets/${encodeURIComponent(targetId)}`);
  }

  async createTargetUpload(options: {
    name: string;
    fileName: string;
    checksumSha256: string;
  }): Promise<TargetUploadResponse> {
    return this.request(targetUploadResponseSchema, "/targets/upload", {
      method: "POST",
      body: JSON.stringify({
        name: options.name,
        fileName: options.fileName,
        contentType: "application/zip",
        // Required by the deployed secure-stack upload contract. Older API
        // revisions ignore this extra field, so sending it is compatible in
        // both directions.
        checksumSha256: options.checksumSha256,
      }),
    });
  }

  async listScans(targetId?: string): Promise<ScanWire[]> {
    const query = new URLSearchParams({ limit: "100" });
    if (targetId !== undefined) query.set("targetId", targetId);
    const page = await this.request(
      scansPageResponseSchema,
      `/scans?${query.toString()}`,
    );
    return page.scans;
  }

  async getScan(scanId: string): Promise<ScanWire> {
    return this.request(scanWireSchema, `/scans/${encodeURIComponent(scanId)}`);
  }

  async startScan(targetId: string): Promise<ScanWire> {
    return this.request(scanWireSchema, "/scans", {
      method: "POST",
      body: JSON.stringify({ targetId }),
    });
  }

  async listArtifacts(scanId: string): Promise<ScanArtifactsResponse> {
    const artifacts = await this.request(
      scanArtifactsResponseSchema,
      `/scans/${encodeURIComponent(scanId)}/artifacts`,
    );
    if (artifacts.scanId.toLowerCase() !== scanId.toLowerCase()) {
      throw new AudixApiError(0, "Artifact listing identity does not match the requested scan.");
    }
    const paths = new Set<string>();
    for (const artifact of artifacts.generatedArtifacts) {
      const destinationIdentity = artifact.relativePath.toLowerCase();
      if (paths.has(destinationIdentity)) {
        throw new AudixApiError(
          0,
          "Artifact listing contains duplicate or case-colliding relative paths.",
        );
      }
      paths.add(destinationIdentity);
    }
    return artifacts;
  }

  async getArtifactDownload(
    scanId: string,
    relativePath: string,
    signal?: AbortSignal,
  ): Promise<ArtifactDownloadResponse> {
    const query = new URLSearchParams({ relativePath });
    const download = await this.request(
      artifactDownloadResponseSchema,
      `/scans/${encodeURIComponent(scanId)}/artifacts/download?${query.toString()}`,
      signal === undefined ? undefined : { signal },
    );
    if (
      download.scanId.toLowerCase() !== scanId.toLowerCase() ||
      download.relativePath !== relativePath
    ) {
      throw new AudixApiError(0, "Artifact download identity does not match the request.");
    }
    assertAllowedPresignedUrl(download.url, "download", this.presignedUrlOrigin);
    return download;
  }

  /**
   * Validate HTTPS, origin, and bucket before uploading bytes to an
   * API-provided destination.
   */
  async performPresignedUpload(
    upload: TargetUploadResponse["upload"],
    archiveBytes: Uint8Array<ArrayBuffer>,
    fileName: string,
  ): Promise<void> {
    assertAllowedPresignedUrl(upload.url, "upload", this.presignedUrlOrigin);
    const expectedBucket = bucketFromOrigin(this.presignedUrlOrigin);
    if (upload.bucket !== expectedBucket) {
      throw new AudixApiError(
        0,
        `Presigned upload bucket '${upload.bucket}' does not match the allowed bucket '${expectedBucket}'.`,
      );
    }
    if (upload.method.toUpperCase() !== "POST") {
      throw new AudixApiError(0, `Unexpected presigned upload method: ${upload.method}`);
    }
    assertAllowedUploadHeaders(upload.headers);
    try {
      await uploadZipToPresignedPost(upload, archiveBytes, fileName);
    } catch (error) {
      throw new AudixUploadAttemptError(error);
    }
  }
}

/**
 * Performs the presigned S3 multipart POST for a zip the user already created;
 * this server never packages directories itself. Fields go
 * first and the file goes last — S3 ignores form fields after the file part.
 * Content-type is left to FormData so the multipart boundary is correct.
 *
 * `redirect: "manual"` is deliberate: a malicious presign envelope could sign
 * a `success_action_redirect` field, and default fetch would follow S3's 303
 * off-origin (turning the POST into a GET to an attacker URL). We never follow
 * — bytes have already landed in the origin-checked bucket, so any 2xx/3xx is
 * a completed upload; only >=400 is a failure.
 */
export async function uploadZipToPresignedPost(
  upload: TargetUploadResponse["upload"],
  archiveBytes: Uint8Array<ArrayBuffer>,
  fileName: string,
  timeoutMs: number = S3_UPLOAD_TIMEOUT_MS,
): Promise<void> {
  if (upload.method.toUpperCase() !== "POST") {
    throw new AudixApiError(0, `Unexpected presigned upload method: ${upload.method}`);
  }
  assertAllowedUploadHeaders(upload.headers);
  const form = new FormData();
  for (const [key, value] of Object.entries(upload.fields)) {
    form.append(key, value);
  }
  const blob = new Blob([archiveBytes], {
    type: upload.fields["Content-Type"] ?? "application/zip",
  });
  form.append("file", blob, fileName);

  const response = await fetch(upload.url, {
    method: "POST",
    body: form,
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (response.status >= 400) {
    const body = await readBoundedText(response, MAX_S3_ERROR_BODY_BYTES).catch(() => "");
    throw new AudixApiError(response.status, `S3 upload failed: ${body.slice(0, 500)}`);
  }
}

const FORBIDDEN_UPLOAD_HEADERS = new Set([
  "authorization",
  "connection",
  "content-length",
  "content-type",
  "cookie",
  "expect",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "set-cookie",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/** The deployed S3 POST contract currently requires no envelope headers. */
export function assertAllowedUploadHeaders(headers: Record<string, string>): void {
  for (const name of Object.keys(headers)) {
    const normalized = name.trim().toLowerCase();
    if (FORBIDDEN_UPLOAD_HEADERS.has(normalized) || normalized.startsWith("proxy-")) {
      throw new AudixApiError(0, `Presigned upload header '${name}' is forbidden.`);
    }
    throw new AudixApiError(
      0,
      `Presigned upload header '${name}' is unsupported; the upload contract allows none.`,
    );
  }
}

const GENERATED_TESTS_PREFIX = "generated-tests/";
export const HARNESS_REPO_DIR = "test/audix/";

/**
 * Where a generated artifact belongs in the user's repo, or `undefined` if the
 * artifact does not map into the harness directory. The service publishes
 * test/audix/<p> as generated-tests/<p>, so only generated-tests/<safe> is
 * accepted. This never trusts the API to hand back a
 * path we'd write elsewhere: the input must be a safe relative path under the
 * prefix, and the mapped result must stay inside test/audix/. Anything else
 * (absolute, traversal, wrong prefix, e.g. ".github/workflows/pwn.yml")
 * returns undefined and the caller refuses to emit a write path for it.
 */
export function harnessRepoPath(relativePath: string): string | undefined {
  if (!isSafeRelativePath(relativePath)) return undefined;
  if (!relativePath.startsWith(GENERATED_TESTS_PREFIX)) return undefined;
  const mapped = `${HARNESS_REPO_DIR}${relativePath.slice(GENERATED_TESTS_PREFIX.length)}`;
  // Redundant with the checks above, but a cheap invariant on the output.
  if (!mapped.startsWith(HARNESS_REPO_DIR) || !isSafeRelativePath(mapped)) return undefined;
  return mapped;
}

/** Newest scan for a target: newest createdAt, lowest id as the tiebreak. */
export function newestScanForTarget(scans: ScanWire[], targetId: string): ScanWire | undefined {
  return scans
    .filter((scan) => scan.targetId === targetId)
    .sort((a, b) => {
      const byCreatedAt = Date.parse(b.createdAt) - Date.parse(a.createdAt);
      if (byCreatedAt !== 0) return byCreatedAt;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    })[0];
}
