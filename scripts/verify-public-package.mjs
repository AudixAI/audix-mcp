#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const expectedFiles = [
  "DISCLOSURE",
  "LICENSE",
  "README.md",
  "dist/api.js",
  "dist/auth-manager.js",
  "dist/config.js",
  "dist/index.js",
  "dist/local-file.js",
  "dist/oauth.js",
  "dist/pkce.js",
  "dist/realtime.js",
  "dist/token-store.js",
  "dist/tools.js",
  "dist/windows-acl.js",
  "dist/zip-listing.js",
  "package.json",
].sort();

const forbiddenContent = [
  ["source map reference", /sourceMappingURL|sourcesContent/],
  ["private key", /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/],
  ["AWS access key", /(?:AKIA|ASIA)[0-9A-Z]{16}/],
  ["GitHub token", /gh[pousr]_[A-Za-z0-9_]{20,}/],
  ["fine-grained GitHub token", /github_pat_[A-Za-z0-9_]{20,}/],
  ["npm token", /npm_[A-Za-z0-9]{20,}/],
  ["OpenAI-style API key", /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/],
  ["Slack token", /xox[baprs]-[A-Za-z0-9-]{20,}/],
  [
    "private implementation reference",
    /\b(?:internal|private)[ \t]+(?:module|repository|runtime|service|tracker)\b/i,
  ],
  ["private work tracker reference", /UI-WORK-TRACKER|\bAUD-[0-9]+\b/],
  ["private pull request reference", /\bPR #[0-9]+\b/],
  ["private design decision label", /\bdecision D-[A-Za-z0-9.-]+\b/i],
  [
    "non-production deployment reference",
    /(?:^|[./_-])(?:staging|non-production|nonproduction)(?:$|[./_-])/i,
  ],
  ["developer home path", /\/(?:Users|home)\/[A-Za-z0-9._-]+\//],
  [
    "internal rollout metadata",
    /goalEvidence|codexCliVersion|rolloutAdapterSchema/,
  ],
];

function expectedPackageMetadata(version) {
  return {
    name: "@audix/mcp",
    version,
    description:
      "Audix MCP server — a secure auth, API, and realtime bridge that lets coding agents upload a Foundry project, receive scan progress, and fetch the generated fuzz harness.",
    type: "module",
    license: "MIT",
    contentPolicy: { class: "dual-use" },
    homepage: "https://audix.ai",
    repository: {
      type: "git",
      url: "git+https://github.com/AudixAI/audix-mcp.git",
    },
    packageManager: "pnpm@10.33.0",
    files: ["dist", "DISCLOSURE"],
    publishConfig: {
      access: "public",
      registry: "https://registry.npmjs.org/",
    },
    bin: { "audix-mcp": "./dist/index.js" },
    engines: { node: ">=22" },
    scripts: {
      build:
        "tsc -p tsconfig.build.json && node -e \"require('node:fs').chmodSync('dist/index.js', 0o755)\"",
      dev: "tsx src/index.ts",
      prepack: "pnpm run build",
      typecheck: "tsc --noEmit",
      test: "vitest run",
    },
    dependencies: {
      "@modelcontextprotocol/sdk": "1.29.0",
      "aws-amplify": "6.18.0",
      yauzl: "3.4.0",
      zod: "4.4.3",
    },
    devDependencies: {
      "@types/node": "24.12.4",
      "@types/yauzl": "3.4.0",
      tsx: "4.23.0",
      typescript: "6.0.3",
      vitest: "4.1.9",
    },
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalJson(value[key])]),
    );
  }
  return value;
}

export function findForbiddenContent(content) {
  return forbiddenContent
    .filter(([, pattern]) => pattern.test(content))
    .map(([label]) => label);
}

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument !== "--pack-destination" && argument !== "--github-output") {
      fail(`Unknown argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      fail(`Missing value for ${argument}`);
    }
    if (argument === "--pack-destination") options.packDestination = value;
    if (argument === "--github-output") options.githubOutput = value;
    index += 1;
  }
  return options;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) {
    const stdout = result.stdout?.trim().slice(0, 2_000) ?? "";
    const stderr = result.stderr?.trim().slice(0, 2_000) ?? "";
    const detail = [stdout, stderr].filter((value) => value !== "").join("\n");
    fail(`${command} failed with exit ${result.status}${detail === "" ? "" : `: ${detail}`}`);
  }
  return result;
}

async function verifyBuildConfiguration() {
  const baseConfig = JSON.parse(
    await readFile(join(packageRoot, "tsconfig.json"), "utf8"),
  );
  const buildConfig = JSON.parse(
    await readFile(join(packageRoot, "tsconfig.build.json"), "utf8"),
  );
  if (baseConfig.compilerOptions?.sourceMap !== false) {
    fail("Public build must keep sourceMap disabled.");
  }
  if (baseConfig.compilerOptions?.declaration !== false) {
    fail("Public build must keep declarations disabled.");
  }
  if (buildConfig.compilerOptions?.removeComments !== true) {
    fail("Public build must strip source comments.");
  }
}

async function extractPackedArtifact(packResult, tarballPath, scratchRoot) {
  const archiveFiles = run("tar", ["-tzf", tarballPath])
    .stdout.trim()
    .split("\n")
    .filter((entry) => entry !== "")
    .sort();
  const expectedArchiveFiles = expectedFiles
    .map((relativePath) => `package/${relativePath}`)
    .sort();
  if (JSON.stringify(archiveFiles) !== JSON.stringify(expectedArchiveFiles)) {
    fail(
      `Tarball entries changed. Expected ${JSON.stringify(expectedArchiveFiles)}, received ${JSON.stringify(archiveFiles)}.`,
    );
  }

  const inspectionRoot = join(scratchRoot, "inspection");
  await mkdir(inspectionRoot, { recursive: true });
  run("tar", ["-xzf", tarballPath, "-C", inspectionRoot]);

  const packedPackage = join(inspectionRoot, "package");
  const packedMetadata = JSON.parse(
    await readFile(join(packedPackage, "package.json"), "utf8"),
  );
  if (
    JSON.stringify(canonicalJson(packedMetadata)) !==
    JSON.stringify(canonicalJson(expectedPackageMetadata(packResult.version)))
  ) {
    fail("Packed package.json differs from the exact public manifest allowlist.");
  }
  return packedPackage;
}

async function verifyPackedFiles(packResult, packedPackage) {
  const actualFiles = packResult.files.map(({ path }) => path).sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    fail(
      `Public package manifest changed. Expected ${JSON.stringify(expectedFiles)}, received ${JSON.stringify(actualFiles)}.`,
    );
  }

  const packageMetadata = JSON.parse(
    await readFile(join(packedPackage, "package.json"), "utf8"),
  );
  const declaredDependencies = new Set(
    Object.keys(packageMetadata.dependencies ?? {}),
  );
  const importedPackages = new Set();

  for (const relativePath of actualFiles) {
    const sourcePath = join(packedPackage, relativePath);
    const fileStat = await lstat(sourcePath);
    if (!fileStat.isFile() || fileStat.isSymbolicLink()) {
      fail(`Public package entry must be a regular file: ${relativePath}`);
    }
    if (fileStat.size === 0) fail(`Public package entry is empty: ${relativePath}`);

    const content = await readFile(sourcePath, "utf8");
    const forbiddenLabels = findForbiddenContent(content);
    if (forbiddenLabels.length > 0) {
      fail(
        `Public package entry ${relativePath} contains forbidden content: ${forbiddenLabels.join(", ")}.`,
      );
    }

    if (relativePath.endsWith(".js")) {
      run(process.execPath, ["--check", sourcePath]);
      const importSpecifiers = [
        ...content.matchAll(/\bfrom\s+["']([^"']+)["']/g),
        ...content.matchAll(/\bimport\s+["']([^"']+)["']/g),
        ...content.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g),
      ].map((match) => match[1]);
      for (const specifier of importSpecifiers) {
        if (specifier.startsWith("node:")) continue;
        if (specifier.startsWith(".")) {
          const importedPath = resolve(dirname(sourcePath), specifier);
          const importedStat = await lstat(importedPath).catch(() => undefined);
          if (importedStat?.isFile() !== true) {
            fail(`${relativePath} imports a missing local module: ${specifier}`);
          }
          continue;
        }
        const segments = specifier.split("/");
        const packageName = specifier.startsWith("@")
          ? segments.slice(0, 2).join("/")
          : segments[0];
        importedPackages.add(packageName);
      }
    }
  }

  if (
    JSON.stringify([...importedPackages].sort()) !==
    JSON.stringify([...declaredDependencies].sort())
  ) {
    fail(
      `Runtime imports ${JSON.stringify([...importedPackages].sort())} do not exactly match declared dependencies ${JSON.stringify([...declaredDependencies].sort())}.`,
    );
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const temporaryRoot = await mkdtemp(join(tmpdir(), "audix-mcp-package-"));
  const packDestination = resolve(options.packDestination ?? temporaryRoot);
  await mkdir(packDestination, { recursive: true });

  try {
    await verifyBuildConfiguration();
    const npm = process.platform === "win32" ? "npm.cmd" : "npm";
    const emptyNpmrc = join(temporaryRoot, "empty.npmrc");
    const npmCache = join(temporaryRoot, "npm-cache");
    await writeFile(emptyNpmrc, "");
    const packed = run(
      npm,
      [
        "pack",
        "--ignore-scripts",
        "--json",
        "--pack-destination",
        packDestination,
      ],
      {
        cwd: packageRoot,
        env: {
          ...process.env,
          NPM_CONFIG_CACHE: npmCache,
          NPM_CONFIG_USERCONFIG: emptyNpmrc,
          npm_config_cache: npmCache,
          npm_config_userconfig: emptyNpmrc,
        },
      },
    );
    const parsed = JSON.parse(packed.stdout);
    if (!Array.isArray(parsed) || parsed.length !== 1) {
      fail("npm pack returned an unexpected result.");
    }
    const packResult = parsed[0];
    if (typeof packResult?.filename !== "string" || !Array.isArray(packResult.files)) {
      fail("npm pack omitted required artifact metadata.");
    }

    const tarballPath = join(packDestination, packResult.filename);
    const tarball = await readFile(tarballPath);
    const tarballSha256 = createHash("sha256").update(tarball).digest("hex");
    const packedPackage = await extractPackedArtifact(
      packResult,
      tarballPath,
      temporaryRoot,
    );
    await verifyPackedFiles(packResult, packedPackage);
    if (options.githubOutput !== undefined) {
      await writeFile(
        options.githubOutput,
        `tarball_name=${packResult.filename}\ntarball_sha256=${tarballSha256}\n`,
        { flag: "a" },
      );
    }

    process.stdout.write(
      `Verified ${packResult.files.length} public package files in ${packResult.filename}.\n`,
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  await main();
}
