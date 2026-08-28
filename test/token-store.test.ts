import { chmod, mkdtemp, mkdir, realpath, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { deleteCredentials, loadCredentials, saveCredentials } from "../src/token-store.js";

async function tempCredentialsPath(): Promise<string> {
  const dir = await mkdtemp(join(await realpath(tmpdir()), "audix-mcp-creds-"));
  return join(dir, "nested", "credentials.json");
}

const CREDENTIALS = {
  refreshToken: "refresh-token-value",
  clientId: "client123",
  email: "dev@example.com",
  obtainedAt: "2026-07-06T12:00:00.000Z",
};

describe("token store", () => {
  it("round-trips credentials and creates parent dirs", async () => {
    const path = await tempCredentialsPath();
    await saveCredentials(path, CREDENTIALS);
    expect(await loadCredentials(path)).toEqual(CREDENTIALS);
  });

  it("writes the file with 0600 permissions", async () => {
    const path = await tempCredentialsPath();
    await saveCredentials(path, CREDENTIALS);
    const mode = (await stat(path)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("re-tightens an existing credential directory to 0700", async () => {
    const dir = await mkdtemp(join(await realpath(tmpdir()), "audix-mcp-weak-creds-"));
    const credentialDir = join(dir, "existing");
    await mkdir(credentialDir, { mode: 0o777 });
    await chmod(credentialDir, 0o777);

    await saveCredentials(join(credentialDir, "credentials.json"), CREDENTIALS);

    expect((await stat(credentialDir)).mode & 0o777).toBe(0o700);
  });

  it("re-tightens permissions when overwriting", async () => {
    const path = await tempCredentialsPath();
    await saveCredentials(path, CREDENTIALS);
    await saveCredentials(path, { ...CREDENTIALS, email: "other@example.com" });
    const mode = (await stat(path)).mode & 0o777;
    expect(mode).toBe(0o600);
    expect((await loadCredentials(path))?.email).toBe("other@example.com");
  });

  it("returns undefined for a missing file and deletes idempotently", async () => {
    const path = await tempCredentialsPath();
    expect(await loadCredentials(path)).toBeUndefined();
    await deleteCredentials(path);
    await saveCredentials(path, CREDENTIALS);
    await deleteCredentials(path);
    expect(await loadCredentials(path)).toBeUndefined();
  });

  it("refuses to write the token through a pre-existing symlink", async () => {
    const dir = await mkdtemp(join(await realpath(tmpdir()), "audix-mcp-symlink-"));
    const realTarget = join(dir, "attacker-owned.json");
    await writeFile(realTarget, "{}");
    const credPath = join(dir, "credentials.json");
    await symlink(realTarget, credPath);

    await expect(saveCredentials(credPath, CREDENTIALS)).rejects.toThrow(/symlink/i);
    // The symlink target must NOT have received the refresh token.
    const { readFile } = await import("node:fs/promises");
    expect(await readFile(realTarget, "utf8")).toBe("{}");
  });

  it("does not follow a symlinked parent-dir entry to leak the token", async () => {
    const dir = await mkdtemp(join(await realpath(tmpdir()), "audix-mcp-symlink2-"));
    const outsideDir = join(dir, "outside");
    await mkdir(outsideDir);
    const symlinkedParent = join(dir, "linked-parent");
    await symlink(outsideDir, symlinkedParent, "dir");
    const credPath = join(symlinkedParent, "credentials.json");

    await expect(saveCredentials(credPath, CREDENTIALS)).rejects.toThrow(/symlinked.*parent/i);
    expect(dirname(credPath)).toBe(symlinkedParent);
    await expect(stat(join(outsideDir, "credentials.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("rejects a writable non-sticky ancestor instead of trusting a nested directory", async () => {
    const dir = await mkdtemp(join(await realpath(tmpdir()), "audix-mcp-unsafe-parent-"));
    const unsafeParent = join(dir, "shared");
    await mkdir(unsafeParent, { mode: 0o777 });
    await chmod(unsafeParent, 0o777);

    await expect(
      saveCredentials(join(unsafeParent, "private", "credentials.json"), CREDENTIALS),
    ).rejects.toThrow(/unsafe writable.*parent/i);
  });
});
