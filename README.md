# @audix/mcp

A local stdio MCP server that lets coding agents (Claude Code, Codex, Cursor,
anything MCP-capable) drive the Audix pipeline: upload a Foundry project,
receive safe realtime scan progress, and pull down the generated fuzz harness.

## Design: thin execution, native realtime

The server is a **thin auth + API bridge**. It never
creates, extracts, or executes files in the user's project:

- **You (the agent) create the project zip** with your own tools; the
  `preview_project_zip` / `upload_project` descriptions carry the recipe. The
  server only *reads* a zip stored inside an authorized project root (a
  read-only, bounded entry listing enforces a known-sensitive-path deny-list,
  refusing loudly on `.env*`, key material, `.git/`, cloud/SSH/CLI credential
  stores, `broadcast/`, and registry credential files such as `.npmrc`) and
  streams it to a presigned S3 POST. Archive names are returned as explicitly
  untrusted data; oversized listings are truncated with exact omitted counts.
- **You write the harness files.** `fetch_harness` downloads nothing — it
  returns one short-lived presigned HTTPS URL per generated file plus the repo
  path it belongs at (`test/audix/...`); the agent fetches them under its own
  permission model.
- **Tokens never appear in tool results.** Login is OAuth PKCE through the
  system browser; the refresh token lives in `~/.audix/credentials.json`
  (`0600` in an owner-only directory) on POSIX, or the user's private
  `%LOCALAPPDATA%\Audix\credentials.json` on Windows. Windows directory and
  file DACLs are reset to the current user's SID with the OS `icacls.exe`
  utility; credential operations fail closed if that private ACL cannot be
  enforced. Access tokens stay in process memory.
- **Scan waiting is event-driven.** The long-lived stdio server opens two
  user-bound AppSync subscriptions after login. It emits standard MCP logging
  notifications containing only `scanId`, `targetId`, and closed public
  status and progress values. No prompts, traces, model output, internal
  service names, or credentials are included.
- **No status loop is required.** Scan execution continues in the Audix
  backend after the start tool returns. `scan_status` remains a one-shot
  reconciliation tool for an explicit request or reconnect recovery.

## Tools

| Tool | What it does |
| --- | --- |
| `login` / `logout` | Browser PKCE login; local session and realtime lifecycle management |
| `list_projects` | Uploaded targets + newest scan each |
| `preview_project_zip` | Read-only zip listing + upload-policy check (nothing extracted) |
| `upload_project` | Policy check → SHA-256-bound presigned POST → optionally starts the first scan (default on) |
| `start_scan` | Start or retry harness generation for an uploaded `targetId` |
| `scan_status` | One authoritative project/scan snapshot for explicit recovery |
| `fetch_harness` | Presigned URL + repo path per generated file + write-it-yourself instructions |

There is no separate target-validation step. Upload and scan start are
distinct API operations. When `upload_project` receives `autoStart: true`, the MCP server
performs the second operation only after the S3 upload succeeds. If scan start
fails, the tool returns the successfully uploaded `targetId` and instructs the
agent to check `scan_status` before calling `start_scan`; it never encourages a
duplicate upload or run.

## Install

Requires Node.js 22 or newer and an Audix account.

```sh
# Claude Code
claude mcp add audix -- npx -y @audix/mcp
```

For other MCP clients, configure `npx` as the command and
`["-y", "@audix/mcp"]` as its arguments. No service configuration is required.
Call the `login` tool first; Audix opens the system browser for secure sign-in.

Claude Code supplies its stable project directory to the server automatically,
so the one-line install needs no extra configuration. Other MCP clients can
authorize local roots through the standard `roots/list` capability; a launcher
without local roots must set `AUDIX_PROJECT_ROOT` to an absolute project path.
Review ordinary source files for embedded secrets before upload; no filename
policy can recognize every credential embedded in code.

The MCP process must stay running for realtime delivery. MCP logging
notifications are standard protocol notifications, but presentation and
whether they re-enter a model turn are client capabilities. The server never
claims that a disconnected or notification-blind client has been resumed;
call `scan_status` once after reconnecting to reconcile persisted state.

## Development

Requires Node.js 22+ and pnpm 10.33.0.

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
node scripts/verify-public-package.mjs
```

The package declares its security-testing capabilities under npm's dual-use
content policy; see [DISCLOSURE](DISCLOSURE). The protected
`publish-mcp.yml` workflow builds and verifies the exact release artifact.
The first release is published from that artifact through an interactive npm
session with 2FA. Later releases are staged by the workflow through npm's
trusted-publishing OIDC flow and require a maintainer to approve the stage
with 2FA. Never commit npm credentials to this repository.

Security reports are handled through GitHub private vulnerability reporting;
see [SECURITY.md](SECURITY.md).
