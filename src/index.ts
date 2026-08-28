#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { AudixApiClient } from "./api.js";
import { AuthManager } from "./auth-manager.js";
import { loadConfig } from "./config.js";
import { RealtimeMonitor } from "./realtime.js";
import { registerTools } from "./tools.js";

// stdout is the MCP protocol channel — anything human-facing goes to stderr.
async function main(): Promise<void> {
  const config = loadConfig();
  const auth = new AuthManager(config);
  const api = new AudixApiClient(config.apiBaseUrl, config.uploadBucketOrigin, auth);

  const server = new McpServer(
    { name: "audix", version: "0.1.1" },
    {
      capabilities: { logging: {} },
      instructions:
        "Audix scans continue in the backend after start_scan or upload_project returns. " +
        "This server keeps a user-bound realtime subscription open and emits " +
        "audix.scan.progress and audix.scan.status logging notifications. Wait for those " +
        "notifications; treat progress as informational. When a status notification reports " +
        "success, call fetch_harness if the user's task requires the generated harness. Use " +
        "scan_status once only for explicit user requests or recovery after a disconnected client.",
    },
  );
  const monitor = new RealtimeMonitor(
    config,
    () => auth.getAccessToken(),
    async (event) => {
      const terminal =
        event.type === "audix.scan.status" &&
        ["success", "failed", "cancelled"].includes(event.status);
      await server.sendLoggingMessage({
        level: terminal ? "notice" : "info",
        logger: "audix.scan",
        data: event,
      });
    },
  );
  registerTools(server, auth, api, monitor, config.projectRoot);

  await server.connect(new StdioServerTransport());
  console.error(`[audix-mcp] ready (api: ${config.apiBaseUrl})`);
}

main().catch((error: unknown) => {
  console.error(`[audix-mcp] fatal: ${(error as Error).message}`);
  process.exit(1);
});
