import { spawn } from "node:child_process";
import { win32 as win32Path } from "node:path";

export type WindowsAclTarget = "directory" | "file";

interface WindowsAclOptions {
  environment?: NodeJS.ProcessEnv;
  spawnProcess?: typeof spawn;
}

function systemExecutable(name: "icacls.exe" | "whoami.exe", env: NodeJS.ProcessEnv): string {
  const systemRoot = env["SystemRoot"] ?? env["WINDIR"];
  if (
    systemRoot === undefined ||
    !win32Path.isAbsolute(systemRoot) ||
    systemRoot.startsWith("\\\\")
  ) {
    throw new Error("Windows SystemRoot is missing or is not an absolute local path.");
  }
  return win32Path.join(win32Path.normalize(systemRoot), "System32", name);
}

async function runWindowsCommand(
  file: string,
  args: string[],
  spawnProcess: typeof spawn,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawnProcess(file, args, {
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code === 0) {
        resolve(stdout);
        return;
      }
      const detail = stderr.trim();
      reject(
        new Error(
          `${win32Path.basename(file)} exited with ${code ?? `signal ${signal ?? "unknown"}`}` +
            (detail === "" ? "." : `: ${detail}`),
        ),
      );
    });
  });
}

/**
 * Replace a Windows credential path's DACL with a single full-control ACE for
 * the current process user. Commands use absolute OS binary paths, argv
 * arrays, and shell:false so neither paths nor principals are command-parsed.
 */
export async function setPrivateWindowsDacl(
  path: string,
  target: WindowsAclTarget,
  options: WindowsAclOptions = {},
): Promise<void> {
  const env = options.environment ?? process.env;
  const spawnProcess = options.spawnProcess ?? spawn;

  try {
    const whoami = systemExecutable("whoami.exe", env);
    const icacls = systemExecutable("icacls.exe", env);
    const identity = await runWindowsCommand(
      whoami,
      ["/user", "/fo", "csv", "/nh"],
      spawnProcess,
    );
    const sid = identity.match(/\bS-\d+(?:-\d+){2,}\b/i)?.[0];
    if (sid === undefined) {
      throw new Error("whoami.exe did not return the current user's SID.");
    }

    const principal = `*${sid}`;
    const grant =
      target === "directory" ? `${principal}:(OI)(CI)F` : `${principal}:F`;
    const runIcacls = (args: string[]) => runWindowsCommand(icacls, args, spawnProcess);

    // /reset removes stale explicit ACEs. Grant the current SID before
    // /inheritance:r removes the reset ACL's inherited entries, leaving only
    // the explicit owner ACE. /L prevents a final-component link from being
    // followed by icacls.
    await runIcacls([path, "/setowner", principal, "/Q", "/L"]);
    await runIcacls([path, "/reset", "/Q", "/L"]);
    await runIcacls([path, "/grant:r", grant, "/Q", "/L"]);
    await runIcacls([path, "/inheritance:r", "/Q", "/L"]);
  } catch (error) {
    throw new Error(
      `Refusing to use the credential store because a private Windows DACL could not be ` +
        `enforced for ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
