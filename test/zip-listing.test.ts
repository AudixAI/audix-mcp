import { describe, expect, it } from "vitest";
import {
  DEFAULT_ZIP_LIMITS,
  evaluateZipPolicy,
  listZipEntries,
  MAX_ZIP_COMPRESSION_RATIO,
  MAX_ZIP_COMPRESSED_BYTES,
  MAX_ZIP_ENTRY_PATH_BYTES,
  MAX_ZIP_ENTRIES,
  type ZipManifest,
} from "../src/zip-listing.js";

// A real archive (foundry.toml + src/ + src/Counter.sol) so listing runs
// against yauzl end-to-end, not a hand-rolled parser.
const FIXTURE_ZIP_BASE64 =
  "UEsDBAoAAAAAAGmP5lzPw4gyHgAAAB4AAAAMABwAZm91bmRyeS50b21sVVQJAAM2JUxqNiVManV4CwABBPUBAAAEAAAAAFtwcm9maWxlLmRlZmF1bHRdCnNyYyA9ICJzcmMiClBLAwQKAAAAAABpj+ZcAAAAAAAAAAAAAAAABAAcAHNyYy9VVAkAAzYlTGo2JUxqdXgLAAEE9QEAAAQAAAAAUEsDBAoAAAAAAGmP5lzwfT8uFAAAABQAAAAPABwAc3JjL0NvdW50ZXIuc29sVVQJAAM2JUxqNiVManV4CwABBPUBAAAEAAAAAGNvbnRyYWN0IENvdW50ZXIge30KUEsBAh4DCgAAAAAAaY/mXM/DiDIeAAAAHgAAAAwAGAAAAAAAAQAAAKSBAAAAAGZvdW5kcnkudG9tbFVUBQADNiVManV4CwABBPUBAAAEAAAAAFBLAQIeAwoAAAAAAGmP5lwAAAAAAAAAAAAAAAAEABgAAAAAAAAAEADtQWQAAABzcmMvVVQFAAM2JUxqdXgLAAEE9QEAAAQAAAAAUEsBAh4DCgAAAAAAaY/mXPB9Py4UAAAAFAAAAA8AGAAAAAAAAQAAAKSBogAAAHNyYy9Db3VudGVyLnNvbFVUBQADNiVManV4CwABBPUBAAAEAAAAAFBLBQYAAAAAAwADAPEAAAD/AAAAAAA=";

function fixtureZip(): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(FIXTURE_ZIP_BASE64, "base64"));
}

function manifestOf(paths: string[]): ZipManifest {
  const entries = paths.map((path) => ({
    path,
    compressedBytes: 10,
    uncompressedBytes: 10,
    isSymbolicLink: false,
  }));
  return {
    entries,
    entryCount: entries.length,
    archiveCompressedBytes: 10 * entries.length,
    totalCompressedBytes: 10 * entries.length,
    totalUncompressedBytes: 10 * entries.length,
  };
}

function storedSymlinkZip(): Uint8Array<ArrayBuffer> {
  const bytes = Buffer.from(FIXTURE_ZIP_BASE64, "base64");
  const centralDirectory = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  if (centralDirectory < 0) throw new Error("Fixture has no central-directory entry.");
  // Mark the first member as created on Unix with an S_IFLNK mode in the
  // central directory. Its payload remains irrelevant: policy must reject on
  // the stored type before anyone can extract it.
  bytes.writeUInt16LE((3 << 8) | 20, centralDirectory + 4);
  bytes.writeUInt32LE((0o120777 << 16) >>> 0, centralDirectory + 38);
  return new Uint8Array(bytes);
}

function zipWithRawNameAndUnicodeAlias(
  rawName: string,
  rawNameCrc32: number,
  utf8 = false,
): Uint8Array<ArrayBuffer> {
  const bytes = Buffer.from(FIXTURE_ZIP_BASE64, "base64");
  const raw = Buffer.from(rawName, "utf8");
  const alias = Buffer.from("src/a.sol", "utf8");
  if (raw.length !== Buffer.byteLength("foundry.toml")) {
    throw new Error("Test raw name must preserve the fixture's central-directory layout.");
  }

  const localHeader = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  const centralDirectory = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  if (localHeader < 0 || centralDirectory < 0) throw new Error("Fixture ZIP layout changed.");
  if (utf8) {
    bytes.writeUInt16LE(bytes.readUInt16LE(localHeader + 6) | 0x800, localHeader + 6);
    bytes.writeUInt16LE(
      bytes.readUInt16LE(centralDirectory + 8) | 0x800,
      centralDirectory + 8,
    );
  }
  raw.copy(bytes, localHeader + 30);
  raw.copy(bytes, centralDirectory + 46);

  const extraLength = bytes.readUInt16LE(centralDirectory + 30);
  const extraStart = centralDirectory + 46 + raw.length;
  const unicodeFieldLength = 5 + alias.length;
  const unicodeFieldTotal = 4 + unicodeFieldLength;
  if (extraLength - unicodeFieldTotal < 4) throw new Error("Fixture extra field is too short.");

  bytes.writeUInt16LE(0x7075, extraStart);
  bytes.writeUInt16LE(unicodeFieldLength, extraStart + 2);
  bytes[extraStart + 4] = 1;
  bytes.writeUInt32LE(rawNameCrc32, extraStart + 5);
  alias.copy(bytes, extraStart + 9);
  const paddingStart = extraStart + unicodeFieldTotal;
  bytes.writeUInt16LE(0xffff, paddingStart);
  bytes.writeUInt16LE(extraLength - unicodeFieldTotal - 4, paddingStart + 2);
  bytes.fill(0, paddingStart + 4, extraStart + extraLength);
  return new Uint8Array(bytes);
}

describe("listZipEntries", () => {
  it("lists entries with sizes from a real archive", async () => {
    const manifest = await listZipEntries(fixtureZip());
    const paths = manifest.entries.map((entry) => entry.path).sort();
    expect(paths).toEqual(["foundry.toml", "src/", "src/Counter.sol"]);
    expect(manifest.entryCount).toBe(3);
    expect(manifest.archiveCompressedBytes).toBeGreaterThan(0);
    expect(manifest.totalCompressedBytes).toBeGreaterThan(0);
    expect(manifest.totalUncompressedBytes).toBeGreaterThan(0);
  });

  it("rejects a non-zip file loudly", async () => {
    await expect(listZipEntries(new TextEncoder().encode("plain text"))).rejects.toThrow(/zip/i);
  });

  it("aborts when the entry count exceeds the limit (DoS guard)", async () => {
    // The 3-entry fixture is inspected with a maxEntries of 2.
    await expect(
      listZipEntries(fixtureZip(), { ...DEFAULT_ZIP_LIMITS, maxEntries: 2 }),
    ).rejects.toThrow(/more than 2 entries/);
  });

  it("aborts when cumulative entry-name bytes exceed the limit", async () => {
    await expect(
      listZipEntries(fixtureZip(), { ...DEFAULT_ZIP_LIMITS, maxPathBytes: 4 }),
    ).rejects.toThrow(/entry names exceed/);
  });

  it("aborts when one entry name exceeds the per-entry path limit", async () => {
    await expect(
      listZipEntries(fixtureZip(), { ...DEFAULT_ZIP_LIMITS, maxEntryPathBytes: 4 }),
    ).rejects.toThrow(/per-entry path limit/);
  });

  it("has a sane production default entry cap", () => {
    expect(MAX_ZIP_ENTRIES).toBeGreaterThanOrEqual(10_000);
  });

  it("rejects an archive over the compressed-size limit", async () => {
    await expect(
      listZipEntries(fixtureZip(), { ...DEFAULT_ZIP_LIMITS, maxCompressedBytes: 32 }),
    ).rejects.toThrow(/compressed-size limit/);
  });

  it("rejects an entry over the per-entry uncompressed-size limit", async () => {
    await expect(
      listZipEntries(fixtureZip(), {
        ...DEFAULT_ZIP_LIMITS,
        maxEntryUncompressedBytes: 8,
      }),
    ).rejects.toThrow(/per-entry limit/);
  });

  it("rejects aggregate uncompressed bytes over the archive limit", async () => {
    await expect(
      listZipEntries(fixtureZip(), {
        ...DEFAULT_ZIP_LIMITS,
        maxTotalUncompressedBytes: 32,
      }),
    ).rejects.toThrow(/aggregate/);
  });

  it("rejects excessive entry and aggregate compression ratios", async () => {
    await expect(
      listZipEntries(fixtureZip(), {
        ...DEFAULT_ZIP_LIMITS,
        maxCompressionRatio: 0.5,
      }),
    ).rejects.toThrow(/compression-ratio/);
  });

  it("uses bounded production defaults", () => {
    expect(MAX_ZIP_COMPRESSED_BYTES).toBe(50 * 1024 * 1024);
    expect(MAX_ZIP_COMPRESSION_RATIO).toBe(100);
    expect(MAX_ZIP_ENTRY_PATH_BYTES).toBe(4 * 1024);
  });

  it("reads Unix external attributes and blocks a stored symlink member", async () => {
    const manifest = await listZipEntries(storedSymlinkZip());
    expect(manifest.entries[0]?.isSymbolicLink).toBe(true);
    expect(evaluateZipPolicy(manifest).denied).toEqual([
      { path: "foundry.toml", reason: "stored symbolic link" },
    ]);
  });

  it("judges the raw worker path instead of a clean Unicode Path alias", async () => {
    const manifest = await listZipEntries(
      zipWithRawNameAndUnicodeAlias(".agents/a.md", 0x06e496bf),
    );

    expect(manifest.entries[0]?.path).toBe(".agents/a.md");
    expect(evaluateZipPolicy(manifest).denied).toEqual([
      { path: ".agents/a.md", reason: "worker-reserved agent-control path" },
    ]);
  });

  it("rejects a raw backslash even when a clean Unicode Path alias hides it", async () => {
    const listing = listZipEntries(
      zipWithRawNameAndUnicodeAlias("src\\evil.sol", 0xf448a847),
    );
    await expect(listing).rejects.toThrow(/backslash/);
    await expect(listing).rejects.not.toThrow(/src\\evil\.sol/);
  });

  it("rejects control characters in raw archive entry names", async () => {
    await expect(
      listZipEntries(zipWithRawNameAndUnicodeAlias("evil\nx.solxx", 0)),
    ).rejects.toThrow(/control or formatting characters/);
  });

  it("rejects bidirectional formatting in decoded archive entry names", async () => {
    await expect(
      listZipEntries(zipWithRawNameAndUnicodeAlias("a\u202ebcdefghi", 0, true)),
    ).rejects.toThrow(/control or formatting characters/);
  });

  it.each(["e\u200bvilx.sol", "e\u200dvilx.sol", "e\u2060vilx.sol", "e\ufeffvilx.sol"])(
    "rejects zero-width formatting in decoded archive entry name %j",
    async (path) => {
      await expect(
        listZipEntries(zipWithRawNameAndUnicodeAlias(path, 0, true)),
      ).rejects.toThrow(/control or formatting characters/);
    },
  );

  it("does not forward a parser-rejected entry name in the error", async () => {
    const listing = listZipEntries(
      zipWithRawNameAndUnicodeAlias("../\nx.solxxx", 0, true),
    );

    await expect(listing).rejects.toThrow(/^Corrupt zip archive\.$/);
    await expect(listing).rejects.not.toThrow(/x\.sol|\n/);
  });
});

describe("evaluateZipPolicy", () => {
  it("passes a clean foundry project", () => {
    const report = evaluateZipPolicy(manifestOf(["foundry.toml", "src/Counter.sol", "test/Counter.t.sol"]));
    expect(report.denied).toEqual([]);
    expect(report.warnings).toEqual([]);
    expect(report.suspiciousPaths).toEqual([]);
  });

  it.each([
    ".env",
    ".env.local",
    "config/.env.production",
    "keys/id_rsa",
    "certs/server.pem",
    "wallet.key",
    ".git/config",
    "proj/.git/HEAD",
    ".aws/credentials",
    ".ENV",
    "certs/SERVER.PEM",
    "keys/ID_RSA.pub",
    ".GIT/config",
    "broadcast/Deploy.s.sol/1/run-latest.json",
    "wrapper/broadcast/Deploy.s.sol/1/run.json",
    ".npmrc",
    "wrapper/.npmrc",
    ".yarnrc.yml",
    ".pnpmrc",
    ".pypirc",
    ".netrc",
    "bunfig.toml",
    "NuGet.Config",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".git-credentials",
    "wrapper/.git-credentials",
    ".ssh/custom_private",
    "wrapper/.GNUPG/private-keys-v1.d/key",
    ".azure/msal_token_cache.json",
    ".kube/config",
    ".docker/config.json",
    ".pulumi/credentials.json",
    "wrapper/.config/gcloud/credentials.db",
    ".config/gh/hosts.yml",
    ".config/rclone/rclone.conf",
    ".config/glab-cli/config.yml",
    ".terraformrc",
    ".terraform.d/credentials.tfrc.json",
  ])("denies %s", (path) => {
    const report = evaluateZipPolicy(manifestOf([path]));
    expect(report.denied).toHaveLength(1);
    expect(report.denied[0]?.path).toBe(path);
  });

  it.each([
    "project/.agents/skills/attack/SKILL.md",
    "project/.codex/config.toml",
    "project/.codex-plugin/plugin.json",
    "project/.git/config",
    "project/AGENTS.md",
    "project/AGENTS.override.md",
    "project/.mcp.json",
    "project/mcp.json",
    "PROJECT/.AGENTS/prompt.md",
    "project/Agents.MD",
    "project/agentſ.md",
  ])("denies worker-reserved path %s", (path) => {
    expect(evaluateZipPolicy(manifestOf([path])).denied).toEqual([
      expect.objectContaining({ path, reason: expect.stringContaining("worker-reserved") }),
    ]);
  });

  it.each(["project/backend.env", "project/backend.env.local", "project/secrets.env.backup"])(
    "matches worker dotenv rejection for %s",
    (path) => {
      expect(evaluateZipPolicy(manifestOf([path])).denied).toHaveLength(1);
    },
  );

  it.each([
    "node_modules/foo/index.js",
    "out/Counter.sol/Counter.json",
    "cache/solidity-files-cache.json",
  ])("warns on %s without blocking", (path) => {
    const report = evaluateZipPolicy(manifestOf([path]));
    expect(report.denied).toEqual([]);
    expect(report.warnings).toHaveLength(1);
  });

  it("does not deny a file merely named like a directory rule", () => {
    const report = evaluateZipPolicy(
      manifestOf([
        "src/environment.ts",
        ".gitignore",
        ".gitmodules",
        ".github/workflows/ci.yml",
        "docs/agents.md.example",
        "src/docker/config.json",
        "fixtures/credentials.json",
        ".git-credentials.example",
        ".config/project/settings.json",
      ]),
    );
    expect(report.denied).toEqual([]);
  });

  it("flags traversal and absolute entry paths as suspicious", () => {
    const report = evaluateZipPolicy(manifestOf(["../escape.sol", "/abs/path.sol", "ok/file.sol"]));
    expect(report.suspiciousPaths.sort()).toEqual(["../escape.sol", "/abs/path.sol"]);
  });

  it("flags windows-style absolute paths", () => {
    const report = evaluateZipPolicy(manifestOf(["C:/temp/x.sol", "a\\..\\b.sol"]));
    expect(report.suspiciousPaths).toHaveLength(2);
  });
});
