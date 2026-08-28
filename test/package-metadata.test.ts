import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

interface PackageMetadata {
  contentPolicy?: { class?: string };
  private?: boolean;
  license?: string;
  homepage?: string;
  files?: string[];
  publishConfig?: { access?: string; registry?: string };
  repository?: { directory?: string; type?: string; url?: string };
  scripts?: Record<string, string>;
}

interface TypeScriptConfig {
  compilerOptions?: {
    declaration?: boolean;
    removeComments?: boolean;
    sourceMap?: boolean;
  };
}

describe("publish metadata", () => {
  it("ships only built public-package files and rebuilds before packing", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as PackageMetadata;

    expect(packageJson.private).toBeUndefined();
    expect(packageJson.license).toBe("MIT");
    expect(packageJson.contentPolicy).toEqual({ class: "dual-use" });
    expect(packageJson.files).toEqual(["dist", "DISCLOSURE"]);
    expect(packageJson.publishConfig).toEqual({
      access: "public",
      registry: "https://registry.npmjs.org/",
    });
    expect(packageJson.homepage).toBe("https://audix.ai");
    expect(packageJson.repository).toEqual({
      type: "git",
      url: "git+https://github.com/AudixAI/audix-mcp.git",
    });
    expect(packageJson.scripts?.["prepack"]).toContain("build");
    expect(packageJson.scripts?.["build"]).toContain("chmodSync");
  });

  it("does not emit source maps, declarations, or private source comments", async () => {
    const compilerConfig = JSON.parse(
      await readFile(new URL("../tsconfig.json", import.meta.url), "utf8"),
    ) as TypeScriptConfig;
    const buildConfig = JSON.parse(
      await readFile(new URL("../tsconfig.build.json", import.meta.url), "utf8"),
    ) as TypeScriptConfig;

    expect(compilerConfig.compilerOptions?.sourceMap).toBe(false);
    expect(compilerConfig.compilerOptions?.declaration).toBe(false);
    expect(buildConfig.compilerOptions?.removeComments).toBe(true);
  });

  it("declares dual-use content and stages automated releases for 2FA approval", async () => {
    const disclosure = await readFile(
      new URL("../DISCLOSURE", import.meta.url),
      "utf8",
    );
    const publishWorkflow = await readFile(
      new URL("../.github/workflows/publish-mcp.yml", import.meta.url),
      "utf8",
    );

    expect(disclosure).toContain("AUDIX MCP DUAL-USE SECURITY DISCLOSURE");
    expect(disclosure).toContain("defensive security testing");
    expect(publishWorkflow).toContain("npm stage publish");
    expect(publishWorkflow).not.toMatch(/\bnpm publish\s+"\$tarball"/);
    expect(publishWorkflow).not.toContain("BOOTSTRAP_NPM_TOKEN");
  });

  it("binds release metadata and runtime identity to the selected package version", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as { version: string };
    const releaseWorkflow = await readFile(
      new URL("../.github/workflows/release-tag.yml", import.meta.url),
      "utf8",
    );
    const runtimeSource = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");

    expect(releaseWorkflow).toContain(
      'package_version="$(git show "${target_sha}:package.json" | jq -r \'.version\')"',
    );
    expect(runtimeSource).toContain(`{ name: "audix", version: "${packageJson.version}" }`);
  });
});
