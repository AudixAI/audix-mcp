import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  readProjectArchiveSnapshot,
  readRegularFileSnapshot,
  sha256Base64,
} from "../src/local-file.js";

async function tempFile(contents: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "audix-mcp-localfile-"));
  const path = join(dir, "project.zip");
  await writeFile(path, contents);
  return path;
}

describe("readRegularFileSnapshot", () => {
  it("reads a regular file through one bounded snapshot", async () => {
    const path = await tempFile("hello");
    const snapshot = await readRegularFileSnapshot(path, 5);
    expect(Buffer.from(snapshot).toString("utf8")).toBe("hello");
  });

  it("rejects a symlink instead of following it", async () => {
    const real = await tempFile("secret");
    const link = `${real}.link`;
    await symlink(real, link);
    await expect(readRegularFileSnapshot(link, 1024)).rejects.toThrow(/symlink/i);
  });

  it("rejects a file over the caller's size bound before returning bytes", async () => {
    await expect(readRegularFileSnapshot(await tempFile("too large"), 4)).rejects.toThrow(
      /compressed-size limit/,
    );
  });

  it("is unaffected by a later pathname overwrite", async () => {
    const path = await tempFile("approved");
    const snapshot = await readRegularFileSnapshot(path, 1024);
    await writeFile(path, "attacker");
    expect(Buffer.from(snapshot).toString("utf8")).toBe("approved");
  });
});

describe("sha256Base64", () => {
  it("streams the canonical base64 SHA-256 digest", async () => {
    expect(sha256Base64(new TextEncoder().encode("hello"))).toBe(
      "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=",
    );
  });
});

describe("readProjectArchiveSnapshot", () => {
  it("accepts relative and absolute archives directly under the project root", async () => {
    const path = await tempFile("approved");
    const root = join(path, "..");
    const canonicalPath = await realpath(path);
    await expect(readProjectArchiveSnapshot(root, "project.zip", 1024)).resolves.toMatchObject({
      path: canonicalPath,
    });
    await expect(readProjectArchiveSnapshot(root, path, 1024)).resolves.toMatchObject({
      path: canonicalPath,
    });
  });

  it("rejects traversal and absolute outside paths while allowing nested in-root archives", async () => {
    const inside = await tempFile("inside");
    const outside = await tempFile("outside");
    const root = join(inside, "..");
    const nested = join(root, "nested");
    await mkdir(nested);
    await writeFile(join(nested, "project.zip"), "nested");

    await expect(readProjectArchiveSnapshot(root, "../outside.zip", 1024)).rejects.toThrow(
      /project root/i,
    );
    await expect(readProjectArchiveSnapshot(root, outside, 1024)).rejects.toThrow(/project root/i);
    await expect(readProjectArchiveSnapshot(root, "nested/project.zip", 1024)).resolves.toMatchObject({
      path: await realpath(join(nested, "project.zip")),
    });
  });

  it("rejects a parent symlink that resolves outside the project root", async () => {
    const inside = await tempFile("inside");
    const outside = await tempFile("outside");
    const root = join(inside, "..");
    await symlink(join(outside, ".."), join(root, "linked"));

    await expect(readProjectArchiveSnapshot(root, "linked/project.zip", 1024)).rejects.toThrow(
      /project root/i,
    );
  });
});
