import { constants as fsConstants } from "node:fs";
import type { Stats } from "node:fs";
import { chmod, lstat, mkdir, open, unlink } from "node:fs/promises";
import { dirname, join, parse, relative, resolve } from "node:path";
import { z } from "zod";
import { assertWindowsCredentialsPath } from "./config.js";
import { setPrivateWindowsDacl } from "./windows-acl.js";

/**
 * The refresh token is the only credential persisted to disk (0600, under
 * ~/.audix/ by default). Access tokens live in memory only and are minted on
 * demand via the refresh grant. Tokens must never appear in MCP tool results.
 */
const storedCredentialsSchema = z.object({
  refreshToken: z.string().min(1),
  clientId: z.string().min(1),
  email: z.string().min(1),
  obtainedAt: z.iso.datetime(),
});

export type StoredCredentials = z.infer<typeof storedCredentialsSchema>;

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

function assertOwnedByCurrentUser(stats: Stats, path: string): void {
  const uid = process.getuid?.();
  if (uid !== undefined && stats.uid !== uid) {
    throw new Error(`Refusing credentials path not owned by the current user: ${path}.`);
  }
}

async function inspectDirectory(path: string): Promise<Stats> {
  const stats = await lstat(path);
  if (stats.isSymbolicLink()) {
    throw new Error(`Refusing a symlinked credentials parent directory: ${path}.`);
  }
  if (!stats.isDirectory()) {
    throw new Error(`Credentials parent is not a directory: ${path}.`);
  }
  return stats;
}

/** Validate every parent and optionally create the owner-only final directory. */
async function prepareCredentialsDirectory(path: string, create: boolean): Promise<boolean> {
  const directory = dirname(path);
  const root = parse(directory).root;
  if (directory === root) {
    throw new Error("Refusing to store credentials directly in a filesystem root.");
  }

  let current = root;
  const segments = relative(root, directory).split(/[\\/]/).filter(Boolean);
  for (const [index, segment] of segments.entries()) {
    current = join(current, segment);
    let stats;
    try {
      stats = await inspectDirectory(current);
    } catch (error) {
      if (!isMissing(error)) throw error;
      if (!create) return false;
      try {
        await mkdir(current, { mode: 0o700 });
      } catch (mkdirError) {
        if ((mkdirError as NodeJS.ErrnoException).code !== "EEXIST") throw mkdirError;
      }
      stats = await inspectDirectory(current);
    }

    const isCredentialsDirectory = index === segments.length - 1;
    if (process.platform === "win32") {
      if (isCredentialsDirectory) await setPrivateWindowsDacl(current, "directory");
      continue;
    }
    if (isCredentialsDirectory) {
      assertOwnedByCurrentUser(stats, current);
      await chmod(current, 0o700);
      const tightened = await inspectDirectory(current);
      assertOwnedByCurrentUser(tightened, current);
      if ((tightened.mode & 0o077) !== 0) {
        throw new Error(`Credentials directory is not owner-only: ${current}.`);
      }
      continue;
    }

    const writableByOthers = (stats.mode & 0o022) !== 0;
    const sticky = (stats.mode & 0o1000) !== 0;
    if (writableByOthers && !sticky) {
      throw new Error(`Refusing unsafe writable credentials parent directory: ${current}.`);
    }
  }
  return true;
}

async function resolvedCredentialsPath(path: string, createDirectory: boolean): Promise<string | undefined> {
  if (process.platform === "win32") assertWindowsCredentialsPath(path);
  const resolvedPath = resolve(path);
  return (await prepareCredentialsDirectory(resolvedPath, createDirectory))
    ? resolvedPath
    : undefined;
}

function assertSafeCredentialFile(
  stats: Stats,
  path: string,
): void {
  if (!stats.isFile()) throw new Error(`Credentials path is not a regular file: ${path}.`);
  assertOwnedByCurrentUser(stats, path);
  if (stats.nlink !== 1) {
    throw new Error(`Refusing multiply-linked credentials file: ${path}.`);
  }
}

export async function saveCredentials(path: string, credentials: StoredCredentials): Promise<void> {
  const safePath = await resolvedCredentialsPath(path, true);
  if (safePath === undefined) throw new Error("Could not create the credentials directory.");

  // Never follow a symlink planted at the credentials path — that would let a
  // local attacker redirect the refresh token into a project/log/synced file.
  // Refuse an existing symlink outright, and open with O_NOFOLLOW so the write
  // itself can't traverse one created between the check and the open.
  try {
    const existing = await lstat(safePath);
    if (existing.isSymbolicLink()) {
      throw new Error(`Refusing to write credentials through a symlink at ${safePath}.`);
    }
    assertSafeCredentialFile(existing, safePath);
  } catch (error) {
    if (!isMissing(error)) throw error;
  }

  const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW;
  const handle = await open(safePath, flags, 0o600);
  try {
    assertSafeCredentialFile(await handle.stat(), safePath);
    // Re-tighten before replacing token bytes in case the file pre-existed
    // (the creation mode only applies to a new file).
    if (process.platform === "win32") {
      await setPrivateWindowsDacl(safePath, "file");
    } else {
      await handle.chmod(0o600);
    }
    await handle.truncate(0);
    await handle.writeFile(JSON.stringify(storedCredentialsSchema.parse(credentials), null, 2));
  } finally {
    await handle.close();
  }
}

export async function loadCredentials(path: string): Promise<StoredCredentials | undefined> {
  const safePath = await resolvedCredentialsPath(path, false);
  if (safePath === undefined) return undefined;
  let handle;
  try {
    handle = await open(safePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error) {
    if (isMissing(error)) return undefined;
    if (["ELOOP", "EMLINK"].includes((error as NodeJS.ErrnoException).code ?? "")) {
      throw new Error(`Refusing to read credentials through a symlink at ${safePath}.`);
    }
    throw error;
  }
  try {
    assertSafeCredentialFile(await handle.stat(), safePath);
    if (process.platform === "win32") {
      await setPrivateWindowsDacl(safePath, "file");
    } else {
      await handle.chmod(0o600);
    }
    return storedCredentialsSchema.parse(JSON.parse(await handle.readFile("utf8")));
  } finally {
    await handle.close();
  }
}

export async function deleteCredentials(path: string): Promise<void> {
  const safePath = await resolvedCredentialsPath(path, false);
  if (safePath === undefined) return;
  let stats;
  try {
    stats = await lstat(safePath);
  } catch (error) {
    if (isMissing(error)) return;
    throw error;
  }
  if (stats.isSymbolicLink()) {
    throw new Error(`Refusing a symlinked credentials path: ${safePath}.`);
  }
  assertSafeCredentialFile(stats, safePath);
  await unlink(safePath);
}
