import { readFileSync } from "node:fs";

type PackageManifest = {
  version?: unknown;
};

export const CLI_VERSION = readCliVersion();

function readCliVersion(): string {
  const manifest = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8")
  ) as PackageManifest;

  if (typeof manifest.version !== "string" || manifest.version.length === 0) {
    throw new Error("CLI package version is missing from package.json.");
  }

  return manifest.version;
}
