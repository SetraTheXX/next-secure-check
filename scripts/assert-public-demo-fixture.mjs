import { execFileSync } from "node:child_process";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const fixturePath = "examples/secure-next-app";
const fixtureDirectory = path.join(repoRoot, fixturePath);
const expectedFiles = [
  `${fixturePath}/README.md`,
  `${fixturePath}/next.config.js`,
  `${fixturePath}/package.json`,
].sort();
const expectedFileSet = new Set(expectedFiles);

try {
  const trackedFiles = execFileSync("git", ["-C", repoRoot, "ls-files", "--", fixturePath], {
    encoding: "utf8",
  }).trim().split(/\r?\n/).filter(Boolean).sort();

  const directories = [fixtureDirectory];
  const actualFiles = [];

  while (directories.length > 0) {
    const currentDirectory = directories.pop();
    const entries = await readdir(currentDirectory, { withFileTypes: true });

    for (const entry of entries) {
      const absolutePath = path.join(currentDirectory, entry.name);
      if (entry.isDirectory()) {
        directories.push(absolutePath);
        continue;
      }

      const relativePath = path.relative(repoRoot, absolutePath).split(path.sep).join("/");
      if (!expectedFileSet.has(relativePath)) {
        throw new Error("unexpected fixture file");
      }
      actualFiles.push(relativePath);
    }
  }

  if (JSON.stringify(trackedFiles) !== JSON.stringify(expectedFiles)
    || JSON.stringify(actualFiles.sort()) !== JSON.stringify(expectedFiles)) {
    throw new Error("fixture inventory mismatch");
  }

  execFileSync("git", ["-C", repoRoot, "diff", "--quiet", "HEAD", "--", ...expectedFiles], {
    stdio: "ignore",
  });

  console.log("Fixture inventory and tracked content verified.");
} catch {
  console.error("Fixture check failed: examples/secure-next-app must contain only its three tracked public files matching HEAD.");
  process.exitCode = 1;
}
