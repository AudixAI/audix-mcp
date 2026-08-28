#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const expectedToolNames = [
  "fetch_harness",
  "list_projects",
  "login",
  "logout",
  "preview_project_zip",
  "scan_status",
  "start_scan",
  "upload_project",
];

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument !== "--tarball" && argument !== "--expected-sha256") {
      fail(`Unknown argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      fail(`Missing value for ${argument}`);
    }
    if (argument === "--tarball") options.tarball = value;
    if (argument === "--expected-sha256") options.expectedSha256 = value;
    index += 1;
  }
  if (options.tarball === undefined || options.expectedSha256 === undefined) {
    fail("Both --tarball and --expected-sha256 are required.");
  }
  if (!/^[a-f0-9]{64}$/.test(options.expectedSha256)) {
    fail("Expected SHA-256 must be 64 lowercase hexadecimal characters.");
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
    fail(
      `${command} failed with exit ${result.status}${detail === "" ? "" : `: ${detail}`}`,
    );
  }
  return result;
}

function safeEnvironment(home, cache) {
  const environment = {
    AUDIX_COGNITO_CLIENT_ID: "public-package-smoke-client",
    HOME: home,
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_CACHE: cache,
    NPM_CONFIG_FUND: "false",
    PATH: process.env.PATH ?? "",
    TMPDIR: join(home, "tmp"),
  };
  if (process.platform === "win32") {
    environment.ComSpec = process.env.ComSpec ?? "";
    environment.SystemRoot = process.env.SystemRoot ?? "";
  }
  return environment;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const tarballPath = resolve(options.tarball);
  const tarball = await readFile(tarballPath);
  const actualSha256 = createHash("sha256").update(tarball).digest("hex");
  if (actualSha256 !== options.expectedSha256) {
    fail("Downloaded tarball digest does not match the verified build artifact.");
  }

  const consumerRoot = await mkdtemp(join(tmpdir(), "audix-mcp-consumer-"));
  try {
    const npm = process.platform === "win32" ? "npm.cmd" : "npm";
    const emptyNpmrc = join(consumerRoot, "empty.npmrc");
    const npmCache = join(consumerRoot, "npm-cache");
    const runtimeTmp = join(consumerRoot, "tmp");
    await mkdir(runtimeTmp, { recursive: true });
    await writeFile(
      join(consumerRoot, "package.json"),
      `${JSON.stringify({ name: "audix-mcp-package-smoke", private: true })}\n`,
    );
    await writeFile(emptyNpmrc, "");
    const environment = {
      ...safeEnvironment(consumerRoot, npmCache),
      NPM_CONFIG_USERCONFIG: emptyNpmrc,
    };
    run(
      npm,
      [
        "install",
        "--ignore-scripts",
        "--omit=dev",
        "--package-lock=false",
        tarballPath,
      ],
      { cwd: consumerRoot, env: environment, timeout: 120_000 },
    );
    run(npm, ["ls", "--omit=dev", "--all"], {
      cwd: consumerRoot,
      env: environment,
    });

    const entrypoint = join(
      consumerRoot,
      "node_modules",
      "@audix",
      "mcp",
      "dist",
      "index.js",
    );
    const input = [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "audix-package-verifier", version: "1.0.0" },
        },
      },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    ]
      .map((message) => JSON.stringify(message))
      .join("\n");
    const smoke = run(process.execPath, [entrypoint], {
      cwd: consumerRoot,
      env: safeEnvironment(consumerRoot, npmCache),
      input: `${input}\n`,
      timeout: 10_000,
    });
    const responses = smoke.stdout
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line));
    const initialize = responses.find((message) => message.id === 1);
    if (typeof initialize?.result?.protocolVersion !== "string") {
      fail("Installed package did not complete the MCP initialize handshake.");
    }
    const tools = responses.find((message) => message.id === 2)?.result?.tools;
    const toolNames = Array.isArray(tools)
      ? tools.map(({ name }) => name).sort()
      : undefined;
    if (JSON.stringify(toolNames) !== JSON.stringify(expectedToolNames)) {
      fail(
        `Installed package exposed unexpected MCP tools: ${JSON.stringify(toolNames)}.`,
      );
    }

    process.stdout.write(
      `Verified isolated consumer install and ${toolNames.length} MCP tools.\n`,
    );
  } finally {
    await rm(consumerRoot, { recursive: true, force: true });
  }
}

await main();
