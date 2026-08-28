import { access, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { browserLaunchSpec, openBrowser } from "../src/auth-manager.js";

const launcher = vi.hoisted(() => ({ spawn: vi.fn(), unref: vi.fn(), on: vi.fn() }));

vi.mock("node:child_process", () => ({ spawn: launcher.spawn }));

describe("openBrowser", () => {
  const originalCwd = process.cwd();

  afterEach(() => {
    process.chdir(originalCwd);
    vi.clearAllMocks();
  });

  it("passes an ampersand-bearing URL as one opaque value from a hostile cwd", async () => {
    const hostileCwd = await mkdtemp(join(tmpdir(), "audix-mcp-browser-"));
    const marker = join(hostileCwd, "executed.txt");
    await writeFile(
      join(hostileCwd, "response_type=code.cmd"),
      `@echo off\r\necho executed>"${marker}"\r\n`,
    );
    process.chdir(hostileCwd);

    const url =
      "https://auth.example/oauth2/authorize?client_id=public&response_type=code&state=s";
    launcher.spawn.mockReturnValue({ unref: launcher.unref, on: launcher.on });
    openBrowser(url);
    await vi.waitFor(() => expect(launcher.spawn).toHaveBeenCalledOnce());

    // URL passed as a single argument, never through a shell — so cmd.exe/start
    // can't parse its `&` as a command separator (MCP-001 regression).
    expect(launcher.spawn).toHaveBeenCalledWith(
      expect.any(String),
      [url],
      expect.objectContaining({ shell: false }),
    );
    expect(launcher.unref).toHaveBeenCalledOnce();
    expect(browserLaunchSpec(url, "win32", String.raw`C:\Windows`)).toEqual({
      file: String.raw`C:\Windows\explorer.exe`,
      arguments: [url],
    });
    await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
