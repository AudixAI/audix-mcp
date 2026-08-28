import yauzl from "yauzl";

/**
 * Read-only zip inspection: the server never extracts or
 * executes archive contents — it lists entries so agents and users can review
 * a manifest, and so uploads can be refused loudly when they contain secrets).
 */
export interface ZipEntrySummary {
  path: string;
  compressedBytes: number;
  uncompressedBytes: number;
  isSymbolicLink: boolean;
}

export interface ZipManifest {
  entries: ZipEntrySummary[];
  entryCount: number;
  archiveCompressedBytes: number;
  totalCompressedBytes: number;
  totalUncompressedBytes: number;
}

/**
 * Bounds on the central directory we're willing to read into memory and
 * serialize into a tool result. A crafted zip with millions of entries would
 * otherwise OOM the server or flood the agent's context — even though we never
 * extract. These are far above any real Foundry project.
 */
export const MAX_ZIP_ENTRIES = 100_000;
export const MAX_ZIP_PATH_BYTES = 8 * 1024 * 1024;
export const MAX_ZIP_ENTRY_PATH_BYTES = 4 * 1024;
export const MAX_ZIP_COMPRESSED_BYTES = 50 * 1024 * 1024;
export const MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES = 64 * 1024 * 1024;
export const MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024;
export const MAX_ZIP_COMPRESSION_RATIO = 100;

export interface ZipListingLimits {
  maxEntries: number;
  maxPathBytes: number;
  maxEntryPathBytes: number;
  maxCompressedBytes: number;
  maxEntryUncompressedBytes: number;
  maxTotalUncompressedBytes: number;
  maxCompressionRatio: number;
}

export const DEFAULT_ZIP_LIMITS: ZipListingLimits = {
  maxEntries: MAX_ZIP_ENTRIES,
  maxPathBytes: MAX_ZIP_PATH_BYTES,
  maxEntryPathBytes: MAX_ZIP_ENTRY_PATH_BYTES,
  maxCompressedBytes: MAX_ZIP_COMPRESSED_BYTES,
  maxEntryUncompressedBytes: MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES,
  maxTotalUncompressedBytes: MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES,
  maxCompressionRatio: MAX_ZIP_COMPRESSION_RATIO,
};

const UNIX_ZIP_HOST = 3;
const UNIX_FILE_TYPE_MASK = 0o170000;
const UNIX_SYMBOLIC_LINK = 0o120000;
const UNSAFE_DISPLAY_CHARACTERS = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

function hasUnsafeRawNameByte(rawName: Buffer): boolean {
  return rawName.some((byte) => byte <= 0x1f || byte === 0x7f);
}

function isStoredSymbolicLink(entry: yauzl.Entry): boolean {
  const hostSystem = (entry.versionMadeBy >>> 8) & 0xff;
  const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
  return hostSystem === UNIX_ZIP_HOST && (unixMode & UNIX_FILE_TYPE_MASK) === UNIX_SYMBOLIC_LINK;
}

function compressionRatioExceeds(
  uncompressedBytes: number,
  compressedBytes: number,
  maxRatio: number,
): boolean {
  return (
    uncompressedBytes > 0 &&
    (compressedBytes === 0 || uncompressedBytes / compressedBytes > maxRatio)
  );
}

/** Decode the central-directory name the same way Python zipfile does. */
function workerArchivePath(entry: yauzl.Entry): string {
  // An empty extra-field list intentionally ignores Info-ZIP's Unicode Path
  // alias. The worker evaluates ZipInfo.orig_filename from the raw central
  // directory, so accepting an alternate alias here would let preview and the
  // worker make security decisions about different paths.
  return yauzl.getFileNameLowLevel(entry.generalPurposeBitFlag, entry.fileNameRaw, [], true);
}

export async function listZipEntries(
  archiveBytes: Uint8Array<ArrayBuffer>,
  limits: ZipListingLimits = DEFAULT_ZIP_LIMITS,
): Promise<ZipManifest> {
  if (archiveBytes.byteLength > limits.maxCompressedBytes) {
    throw new Error(
      `Zip is ${archiveBytes.byteLength} bytes; compressed-size limit is ${limits.maxCompressedBytes} bytes.`,
    );
  }
  const zipBuffer = Buffer.from(
    archiveBytes.buffer,
    archiveBytes.byteOffset,
    archiveBytes.byteLength,
  );
  const entries = await new Promise<ZipEntrySummary[]>((resolve, reject) => {
    const collected: ZipEntrySummary[] = [];
    let pathBytes = 0;
    let totalCompressedBytes = 0;
    let totalUncompressedBytes = 0;
    yauzl.fromBuffer(zipBuffer, { lazyEntries: true, strictFileNames: true }, (error, zipFile) => {
      if (error) {
        reject(new Error("Not a readable zip archive."));
        return;
      }
      const abort = (message: string) => {
        zipFile.close();
        reject(new Error(message));
      };
      zipFile.on("entry", (entry: yauzl.Entry) => {
        const entryNumber = collected.length + 1;
        const archivePath = workerArchivePath(entry);
        const archivePathBytes = Buffer.byteLength(archivePath, "utf8");
        if (
          hasUnsafeRawNameByte(entry.fileNameRaw) ||
          UNSAFE_DISPLAY_CHARACTERS.test(archivePath)
        ) {
          abort(
            "Zip entry name contains control or formatting characters; " +
              "refusing to inspect it.",
          );
          return;
        }
        if (archivePathBytes > limits.maxEntryPathBytes) {
          abort(
            `Zip entry name is ${archivePathBytes} bytes; per-entry path limit is ` +
              `${limits.maxEntryPathBytes} bytes.`,
          );
          return;
        }
        if (archivePath.includes("\\")) {
          abort(`Zip entry #${entryNumber} contains a backslash; refusing to inspect it.`);
          return;
        }
        collected.push({
          path: archivePath,
          compressedBytes: entry.compressedSize,
          uncompressedBytes: entry.uncompressedSize,
          isSymbolicLink: isStoredSymbolicLink(entry),
        });
        pathBytes += archivePathBytes;
        totalCompressedBytes += entry.compressedSize;
        totalUncompressedBytes += entry.uncompressedSize;
        if (collected.length > limits.maxEntries) {
          abort(`Zip has more than ${limits.maxEntries} entries; refusing to inspect it.`);
          return;
        }
        if (pathBytes > limits.maxPathBytes) {
          abort(`Zip entry names exceed ${limits.maxPathBytes} bytes; refusing to inspect it.`);
          return;
        }
        if (entry.uncompressedSize > limits.maxEntryUncompressedBytes) {
          abort(
            `Zip entry #${entryNumber} expands to ${entry.uncompressedSize} bytes; ` +
              `per-entry limit is ${limits.maxEntryUncompressedBytes} bytes.`,
          );
          return;
        }
        if (totalUncompressedBytes > limits.maxTotalUncompressedBytes) {
          abort(
            `Zip expands to more than ${limits.maxTotalUncompressedBytes} bytes in aggregate.`,
          );
          return;
        }
        if (
          compressionRatioExceeds(
            entry.uncompressedSize,
            entry.compressedSize,
            limits.maxCompressionRatio,
          )
        ) {
          abort(
            `Zip entry #${entryNumber} exceeds the ${limits.maxCompressionRatio}:1 ` +
              `compression-ratio limit.`,
          );
          return;
        }
        if (
          compressionRatioExceeds(
            totalUncompressedBytes,
            totalCompressedBytes,
            limits.maxCompressionRatio,
          )
        ) {
          abort(`Zip exceeds the ${limits.maxCompressionRatio}:1 aggregate compression-ratio limit.`);
          return;
        }
        zipFile.readEntry();
      });
      zipFile.on("end", () => resolve(collected));
      // yauzl validates some names before emitting an entry and includes the
      // attacker-controlled name in its error. Never forward parser details to
      // an MCP text result; all accepted names are validated in the callback.
      zipFile.on("error", () => reject(new Error("Corrupt zip archive.")));
      zipFile.readEntry();
    });
  });

  return {
    entries,
    entryCount: entries.length,
    archiveCompressedBytes: archiveBytes.byteLength,
    totalCompressedBytes: entries.reduce((sum, entry) => sum + entry.compressedBytes, 0),
    totalUncompressedBytes: entries.reduce((sum, entry) => sum + entry.uncompressedBytes, 0),
  };
}

/**
 * Hard deny-list: entries that must never leave the user's machine. A match
 * fails the upload loudly (assert-first) — the agent fixes the zip and
 * retries. Kept deliberately tight; bloat-only concerns are warnings.
 */
const WORKER_RESERVED_SEGMENTS = new Set([".agents", ".codex", ".codex-plugin", ".git"]);
const WORKER_RESERVED_FILE_NAMES = new Set([
  ".mcp.json",
  "agents.md",
  "agents.override.md",
  "mcp.json",
]);
const SENSITIVE_CREDENTIAL_DIRECTORIES = new Set([".ssh", ".gnupg", ".azure", ".kube"]);

const DENY_RULES: ReadonlyArray<{ reason: string; test: (segments: string[]) => boolean }> = [
  {
    reason: "worker-reserved agent-control path",
    test: (segments) => segments.some((segment) => WORKER_RESERVED_SEGMENTS.has(segment)),
  },
  {
    reason: "worker-reserved agent-control file",
    test: (segments) => {
      const fileName = segments.at(-1);
      return fileName !== undefined && WORKER_RESERVED_FILE_NAMES.has(fileName);
    },
  },
  {
    reason: "environment file — likely contains secrets",
    test: (segments) => {
      const fileName = segments.at(-1);
      return (
        fileName !== undefined &&
        (fileName.startsWith(".env") || fileName.endsWith(".env") || fileName.includes(".env."))
      );
    },
  },
  {
    reason: "private key material",
    test: (segments) =>
      segments.some(
        (s) =>
          s.startsWith("id_rsa") ||
          s.startsWith("id_ed25519") ||
          s.startsWith("id_ecdsa") ||
          s.endsWith(".pem") ||
          s.endsWith(".key") ||
          s.endsWith(".p12") ||
          s.endsWith(".pfx") ||
          s.endsWith(".keystore"),
      ),
  },
  {
    reason: "cloud credentials directory (.aws/)",
    test: (segments) => segments.slice(0, -1).includes(".aws"),
  },
  {
    reason: "user credential directory",
    test: (segments) =>
      segments.slice(0, -1).some((segment) => SENSITIVE_CREDENTIAL_DIRECTORIES.has(segment)),
  },
  {
    reason: "common developer credential store",
    test: (segments) => {
      const fileName = segments.at(-1);
      if (fileName === ".git-credentials" || fileName === ".terraformrc") return true;
      if (segments.includes(".docker") && fileName === "config.json") return true;
      if (segments.includes(".pulumi") && fileName === "credentials.json") return true;
      if (segments.includes(".config") && segments.includes("gcloud")) return true;
      if (segments.includes(".config") && segments.includes("rclone")) return true;
      if (segments.includes(".config") && segments.includes("gh") && fileName === "hosts.yml") {
        return true;
      }
      if (
        segments.includes(".config") &&
        segments.includes("glab-cli") &&
        fileName === "config.yml"
      ) {
        return true;
      }
      return (
        segments.includes(".terraform.d") && fileName === "credentials.tfrc.json"
      );
    },
  },
  {
    reason: "foundry broadcast logs (broadcast/) — can embed private keys from past deploys",
    test: (segments) => segments.slice(0, -1).includes("broadcast"),
  },
  {
    reason: "package registry configuration — can contain authentication tokens",
    test: (segments) => {
      const fileName = segments.at(-1);
      return (
        fileName !== undefined &&
        [
          ".npmrc",
          ".yarnrc",
          ".yarnrc.yml",
          ".yarnrc.yaml",
          ".pnpmrc",
          ".pypirc",
          ".netrc",
          "_netrc",
          "bunfig.toml",
          "nuget.config",
          "pip.conf",
          "pip.ini",
        ].includes(fileName)
      );
    },
  },
  {
    reason: "package registry credentials",
    test: (segments) => {
      const fileName = segments.at(-1);
      return (
        (segments.includes(".cargo") &&
          (fileName === "credentials" || fileName === "credentials.toml")) ||
        (segments.includes(".gem") && fileName === "credentials")
      );
    },
  },
];

const WARN_RULES: ReadonlyArray<{ reason: string; test: (segments: string[]) => boolean }> = [
  {
    reason: "dependency/build output (node_modules/, out/, cache/) — bloats the upload; exclude it",
    test: (segments) =>
      segments.slice(0, -1).some((s) => s === "node_modules" || s === "out" || s === "cache"),
  },
];

export interface ZipPolicyFinding {
  path: string;
  reason: string;
}

export interface ZipPolicyReport {
  denied: ZipPolicyFinding[];
  warnings: ZipPolicyFinding[];
  /** Entries whose paths escape a plain extraction dir (absolute or `..`). */
  suspiciousPaths: string[];
}

export function evaluateZipPolicy(manifest: ZipManifest): ZipPolicyReport {
  const denied: ZipPolicyFinding[] = [];
  const warnings: ZipPolicyFinding[] = [];
  const suspiciousPaths = new Set<string>();

  for (const entry of manifest.entries) {
    if (entry.isSymbolicLink) {
      denied.push({ path: entry.path, reason: "stored symbolic link" });
      continue;
    }
    const normalized = entry.path.replaceAll("\\", "/");
    if (entry.path.includes("\\")) suspiciousPaths.add(entry.path);
    if (normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized)) {
      suspiciousPaths.add(entry.path);
    }
    // Compatibility normalization plus lowercasing safely covers the ASCII
    // worker-reserved names even when an archive uses Unicode case-fold forms.
    const segments = normalized
      .split("/")
      .filter((segment) => segment !== "")
      .map((segment) => segment.normalize("NFKC").toLowerCase());
    if (segments.includes("..")) suspiciousPaths.add(entry.path);

    const denyRule = DENY_RULES.find((rule) => rule.test(segments));
    if (denyRule) {
      denied.push({ path: entry.path, reason: denyRule.reason });
      continue;
    }
    const warnRule = WARN_RULES.find((rule) => rule.test(segments));
    if (warnRule) warnings.push({ path: entry.path, reason: warnRule.reason });
  }

  return { denied, warnings, suspiciousPaths: [...suspiciousPaths] };
}
