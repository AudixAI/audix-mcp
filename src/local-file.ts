import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

export interface ProjectArchiveSnapshot {
  path: string;
  bytes: Uint8Array<ArrayBuffer>;
}

/**
 * Authorize an archive against the workspace captured at server startup. The
 * archive path must remain inside that root after both lexical and canonical
 * resolution, which rejects traversal and parent-symlink escapes.
 */
export async function readProjectArchiveSnapshot(
  projectRoot: string,
  requestedPath: string,
  maxBytes: number,
): Promise<ProjectArchiveSnapshot> {
  const canonicalRoot = await realpath(projectRoot);
  const candidate = isAbsolute(requestedPath) ? requestedPath : resolve(canonicalRoot, requestedPath);
  if (!isAbsolute(requestedPath)) {
    const lexicalRelative = relative(canonicalRoot, candidate);
    if (
      lexicalRelative === "" ||
      lexicalRelative.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
      lexicalRelative === ".." ||
      isAbsolute(lexicalRelative)
    ) {
      throw new Error("Project archive must be a file inside the configured Audix project root.");
    }
  }

  const canonicalCandidate = await realpath(candidate);
  const canonicalRelative = relative(canonicalRoot, canonicalCandidate);
  if (
    canonicalRelative === "" ||
    canonicalRelative.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    canonicalRelative === ".." ||
    isAbsolute(canonicalRelative)
  ) {
    throw new Error("Project archive must be a file inside the configured Audix project root.");
  }
  return {
    path: canonicalCandidate,
    bytes: await readRegularFileSnapshot(canonicalCandidate, maxBytes),
  };
}

/**
 * Open a regular file exactly once without following its final path component,
 * then copy its bounded contents into an in-memory snapshot. Every subsequent
 * archive operation uses these same bytes, so pathname swaps cannot separate
 * policy inspection from hashing or upload.
 */
export async function readRegularFileSnapshot(
  path: string,
  maxBytes: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const beforeOpen = await lstat(path);
  if (beforeOpen.isSymbolicLink()) {
    throw new Error(`Refusing to use a symlink at ${path}.`);
  }
  if (!beforeOpen.isFile()) {
    throw new Error(`Not a regular file: ${path}.`);
  }
  if (beforeOpen.size > maxBytes) {
    throw new Error(
      `File is ${beforeOpen.size} bytes; compressed-size limit is ${maxBytes} bytes.`,
    );
  }

  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error) {
    if (["ELOOP", "EMLINK"].includes((error as NodeJS.ErrnoException).code ?? "")) {
      throw new Error(`Refusing to use a symlink at ${path}.`);
    }
    throw error;
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile()) throw new Error(`Not a regular file: ${path}.`);
    if (opened.dev !== beforeOpen.dev || opened.ino !== beforeOpen.ino) {
      throw new Error(`${path} changed while it was being opened; refusing to inspect it.`);
    }
    if (opened.size > maxBytes) {
      throw new Error(`File is ${opened.size} bytes; compressed-size limit is ${maxBytes} bytes.`);
    }
    const raw = await handle.readFile();
    if (raw.byteLength > maxBytes) {
      throw new Error(`File exceeds the compressed-size limit of ${maxBytes} bytes.`);
    }
    const snapshot = new Uint8Array(raw.byteLength);
    snapshot.set(raw);
    return snapshot;
  } finally {
    await handle.close();
  }
}

/**
 * Canonical base64 SHA-256 of the immutable archive snapshot. The upload API
 * binds this digest into the presigned S3 contract.
 */
export function sha256Base64(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("base64");
}
