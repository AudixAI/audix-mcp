import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { setPrivateWindowsDacl } from "../src/windows-acl.js";

function completedChild(stdoutText: string, exitCode = 0) {
  const child = new EventEmitter() as EventEmitter & {
    stdout: PassThrough;
    stderr: PassThrough;
  };
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  queueMicrotask(() => {
    child.stdout.end(stdoutText);
    child.stderr.end(exitCode === 0 ? "" : "Access is denied.");
    child.emit("close", exitCode, null);
  });
  return child;
}

describe("setPrivateWindowsDacl", () => {
  const systemRoot = String.raw`C:\Windows`;
  const credentialPath = String.raw`C:\Users\alice\AppData\Local\Audix\credentials.json`;
  const sid = "S-1-5-21-111-222-333-1001";

  it.each([
    ["file", `*${sid}:F`],
    ["directory", `*${sid}:(OI)(CI)F`],
  ] as const)("uses absolute no-shell commands for an owner-only %s ACL", async (target, grant) => {
    const spawnProcess = vi.fn((file: string) =>
      completedChild(file.endsWith("whoami.exe") ? `"WORKSTATION\\alice","${sid}"\r\n` : ""),
    );

    await setPrivateWindowsDacl(credentialPath, target, {
      environment: { SystemRoot: systemRoot },
      spawnProcess: spawnProcess as never,
    });

    const safeOptions = {
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    };
    expect(spawnProcess.mock.calls).toEqual([
      [
        String.raw`C:\Windows\System32\whoami.exe`,
        ["/user", "/fo", "csv", "/nh"],
        safeOptions,
      ],
      [
        String.raw`C:\Windows\System32\icacls.exe`,
        [credentialPath, "/setowner", `*${sid}`, "/Q", "/L"],
        safeOptions,
      ],
      [
        String.raw`C:\Windows\System32\icacls.exe`,
        [credentialPath, "/reset", "/Q", "/L"],
        safeOptions,
      ],
      [
        String.raw`C:\Windows\System32\icacls.exe`,
        [credentialPath, "/grant:r", grant, "/Q", "/L"],
        safeOptions,
      ],
      [
        String.raw`C:\Windows\System32\icacls.exe`,
        [credentialPath, "/inheritance:r", "/Q", "/L"],
        safeOptions,
      ],
    ]);
  });

  it("fails closed when icacls cannot enforce the DACL", async () => {
    const spawnProcess = vi
      .fn()
      .mockImplementationOnce(() => completedChild(`"WORKSTATION\\alice","${sid}"\r\n`))
      .mockImplementationOnce(() => completedChild("", 5));

    await expect(
      setPrivateWindowsDacl(credentialPath, "file", {
        environment: { SystemRoot: systemRoot },
        spawnProcess: spawnProcess as never,
      }),
    ).rejects.toThrow(/Refusing.*private Windows DACL.*Access is denied/i);
  });

  it("rejects a missing or non-local SystemRoot before spawning", async () => {
    const spawnProcess = vi.fn();

    await expect(
      setPrivateWindowsDacl(credentialPath, "file", {
        environment: { SystemRoot: String.raw`\\attacker\share\Windows` },
        spawnProcess: spawnProcess as never,
      }),
    ).rejects.toThrow(/Refusing.*private Windows DACL.*SystemRoot.*absolute local path/i);
    expect(spawnProcess).not.toHaveBeenCalled();
  });
});
