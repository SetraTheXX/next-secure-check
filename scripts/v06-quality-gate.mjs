import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const cliPath = path.join(repoRoot, "packages", "cli", "dist", "index.js");
const legacyGatePath = path.join(repoRoot, "scripts", "v05-release-gate.mjs");
const publishedCliVersion = "0.5.0";
const candidateCliVersion = "0.6.0";
const developmentRuleIds = [
  "auth/server-action-without-guards",
  "auth/session-cookie-without-security-flags",
  "config/next-image-domains",
  "redirect/unvalidated-target",
  "ssrf/unvalidated-outbound-url",
];
const temporaryDirectories = [];

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) {
    fail(message);
  }
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });

  if (result.error) {
    fail(`Command could not start: ${command} ${args.join(" ")} (${result.error.message})`);
  }

  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function runNode(args, options = {}) {
  return runCommand(process.execPath, args, options);
}

function runCli(target, options = []) {
  return runNode([cliPath, "scan", target, ...options]);
}

function requireSuccess(result, label) {
  assert(result.status === 0, `${label} failed with exit code ${result.status}`);
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch {
    fail(`${label} did not produce valid JSON`);
  }
}

function withoutVolatileMetadata(report) {
  const copy = JSON.parse(JSON.stringify(report));
  if (copy.metadata) {
    delete copy.metadata.scannedAt;
    delete copy.metadata.durationMs;
  }
  return copy;
}

function stableJson(value) {
  return JSON.stringify(value);
}

const WINDOWS_ABSOLUTE_PATH = /(?:^|[^A-Za-z0-9])(?:[A-Za-z]:[\\/]|\\\\[A-Za-z0-9])/;
const POSIX_ABSOLUTE_PATH = /\/(?:Users|home|runner|tmp|workspace)\//;

function assertPublicOutput(text, label) {
  assert(!WINDOWS_ABSOLUTE_PATH.test(text), `${label} leaked an absolute Windows path`);
  assert(!POSIX_ABSOLUTE_PATH.test(text), `${label} leaked an absolute POSIX path`);
}

function findingInventory(findings) {
  const inventory = new Map();
  for (const finding of findings) {
    const key = [finding.ruleId, finding.context ?? "unknown", finding.severity, finding.confidence].join("|");
    inventory.set(key, (inventory.get(key) ?? 0) + 1);
  }
  return Object.fromEntries([...inventory.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

async function makeFixtureProject(prefix, files) {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(directory);
  await writeFile(
    path.join(directory, "package.json"),
    JSON.stringify({ name: prefix, private: true, dependencies: { next: "16.3.2" } }, null, 2),
  );

  await Promise.all(
    Object.entries(files).map(async ([relativePath, contents]) => {
      const target = path.join(directory, relativePath);
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, contents);
    }),
  );

  return directory;
}

const positiveFixture = {
  "app/actions.ts": [
    '"use server";',
    "export async function saveProfile(input) {",
    "  return persist(input);",
    "}",
  ].join("\n"),
  "app/redirect/page.tsx": [
    'import { redirect } from "next/navigation";',
    "export default function Page({ searchParams }) {",
    "  const target = searchParams.get('next');",
    "  redirect(target);",
    "}",
  ].join("\n"),
  "app/api/proxy/route.ts": [
    "export async function POST(request) {",
    "  const url = request.query.url;",
    "  await fetch(url);",
    "}",
  ].join("\n"),
  "app/api/session/route.ts": [
    'import { cookies } from "next/headers";',
    "export async function POST() {",
    '  cookies().set("session", "value", { secure: true });',
    "}",
  ].join("\n"),
  "next.config.mjs": 'export default { images: { domains: ["cdn.example.com"] } };\n',
};

const safeFixture = {
  "app/actions.ts": [
    '"use server";',
    'import { auth } from "next-auth";',
    "export async function saveProfile(input) {",
    "  const session = await auth();",
    "  const parsed = schema.safeParse(input);",
    "  return { session, parsed };",
    "}",
  ].join("\n"),
  "app/redirect/page.tsx": [
    'import { redirect } from "next/navigation";',
    "const ALLOWED_PATHS = ['/dashboard', '/settings'];",
    "export default function Page({ searchParams }) {",
    "  const target = searchParams.get('next');",
    "  if (!ALLOWED_PATHS.includes(target)) return null;",
    "  redirect(target);",
    "}",
  ].join("\n"),
  "app/api/proxy/route.ts": [
    'const ALLOWED_HOSTS = ["api.example.com"];',
    "export async function POST(request) {",
    "  const url = request.query.url;",
    "  if (!ALLOWED_HOSTS.includes(new URL(url).hostname)) return Response.json({ ok: false });",
    "  await fetch(url);",
    "}",
  ].join("\n"),
  "app/api/session/route.ts": [
    'import { cookies } from "next/headers";',
    "export async function POST() {",
    '  cookies().set("session", "value", { httpOnly: true, secure: true, sameSite: "lax" });',
    "}",
  ].join("\n"),
  "next.config.mjs": [
    "export default {",
    "  images: {",
    '    remotePatterns: [{ protocol: "https", hostname: "cdn.example.com", pathname: "/assets/**" }],',
    "  },",
    "};",
  ].join("\n"),
};

async function checkDevelopmentRuleMatrix() {
  const positiveDirectory = await makeFixtureProject("next-secure-check-v06-positive-", positiveFixture);
  const safeDirectory = await makeFixtureProject("next-secure-check-v06-safe-", safeFixture);
  const targets = [
    { name: "positive", directory: positiveDirectory },
    { name: "safe", directory: safeDirectory },
  ];
  const reports = {};

  for (const target of targets) {
    const first = runCli(target.directory, ["--preset", "strict", "--format", "json"]);
    const second = runCli(target.directory, ["--preset", "strict", "--format", "json"]);
    requireSuccess(first, `${target.name} v0.6 matrix scan`);
    requireSuccess(second, `${target.name} repeated v0.6 matrix scan`);

    const firstReport = parseJson(first.stdout, `${target.name} v0.6 matrix scan`);
    const secondReport = parseJson(second.stdout, `${target.name} repeated v0.6 matrix scan`);
    assert(stableJson(withoutVolatileMetadata(firstReport)) === stableJson(withoutVolatileMetadata(secondReport)), `${target.name} v0.6 matrix report is not deterministic`);
    assertPublicOutput(first.stdout, `${target.name} v0.6 matrix JSON`);
    reports[target.name] = firstReport;
  }

  const positiveFindings = reports.positive.findings ?? [];
  const safeFindings = reports.safe.findings ?? [];
  for (const ruleId of developmentRuleIds) {
    const positiveMatches = positiveFindings.filter((finding) => finding.ruleId === ruleId);
    const safeMatches = safeFindings.filter((finding) => finding.ruleId === ruleId);
    assert(positiveMatches.length > 0, `v0.6 matrix did not exercise ${ruleId}`);
    assert(safeMatches.length === 0, `v0.6 safe matrix unexpectedly reported ${ruleId}`);
    assert(positiveMatches.every((finding) => typeof finding.evidence === "string" && finding.evidence.length > 0), `${ruleId} did not expose bounded evidence`);
  }

  const exercised = new Set(positiveFindings.filter((finding) => developmentRuleIds.includes(finding.ruleId)).map((finding) => finding.ruleId));
  assert(exercised.size === developmentRuleIds.length, `v0.6 matrix exercised ${exercised.size}/${developmentRuleIds.length} development rules`);
  console.log(`[v06] development matrix passed: ${exercised.size} positive and safe rule contracts; deterministic JSON and bounded evidence`);
  console.log(`[v06] development inventory: ${JSON.stringify(findingInventory(positiveFindings.filter((finding) => developmentRuleIds.includes(finding.ruleId))))}`);
}

function checkCliSmoke() {
  const version = runNode([cliPath, "--version"]);
  requireSuccess(version, "CLI version smoke");
  assert(version.stdout.trim() === candidateCliVersion, `CLI candidate version changed: expected ${candidateCliVersion}, received ${version.stdout.trim()}`);

  const rootHelp = runNode([cliPath, "--help"]);
  requireSuccess(rootHelp, "CLI root help smoke");
  assert(rootHelp.stdout.includes("scan") && rootHelp.stdout.includes("rules") && rootHelp.stdout.includes("explain"), "CLI root help is missing a public command");

  const rules = runNode([cliPath, "rules"]);
  requireSuccess(rules, "CLI rules smoke");
  assert(rules.stdout.includes("Total rules: 25"), "CLI rules smoke did not expose the 25-rule development line");
  for (const ruleId of developmentRuleIds) {
    assert(rules.stdout.includes(ruleId), `CLI rules smoke is missing ${ruleId}`);
  }

  const explanation = runNode([cliPath, "explain", "ssrf/unvalidated-outbound-url"]);
  requireSuccess(explanation, "CLI explanation smoke");
  assert(explanation.stdout.includes("Rule: ssrf/unvalidated-outbound-url"), "CLI explanation smoke returned the wrong rule");

  const unknown = runNode([cliPath, "explain", "v06/not-a-rule"]);
  assert(unknown.status !== 0, "unknown rule explanation should fail");

  const secure = runCli("examples/secure-next-app", ["--preset", "app", "--summary", "--fail-on", "high"]);
  requireSuccess(secure, "secure fail-on smoke");
  const vulnerable = runCli("examples/vulnerable-next-app", ["--preset", "strict", "--summary", "--fail-on", "high"]);
  assert(vulnerable.status !== 0, "vulnerable fail-on high smoke should fail");
  console.log("[v06] CLI smoke passed: version, help, 25-rule list, explanation, unknown-rule rejection, and fail-on behavior");
}

async function checkPackageContract() {
  const packagePaths = [
    "packages/cli/package.json",
    "packages/core/package.json",
    "packages/rules/package.json",
    "packages/reporter/package.json",
  ];
  const packages = await Promise.all(packagePaths.map(async (relativePath) => ({
    relativePath,
    manifest: JSON.parse(await readFile(path.join(repoRoot, relativePath), "utf8")),
  })));

  for (const { relativePath, manifest } of packages) {
    assert(manifest.version === candidateCliVersion, `${relativePath} candidate version drifted from ${candidateCliVersion}`);
    assert(manifest.engines?.node === ">=20.9.0", `${relativePath} must declare the workspace Node baseline >=20.9.0`);
    assert(manifest.license === "MIT", `${relativePath} is missing the MIT license metadata`);
    assert(Array.isArray(manifest.files) && manifest.files.includes("dist"), `${relativePath} does not publish dist`);
  }

  const action = await readFile(path.join(repoRoot, "action.yml"), "utf8");
  assert(action.includes(`next-secure-check@${publishedCliVersion}`), "Action is not pinned to the published CLI line");
  assert(action.includes("actions/setup-node@v7") && action.includes("node-version: 20"), "Action Node setup contract changed");

  const readme = await readFile(path.join(repoRoot, "README.md"), "utf8");
  assert(readme.includes("v0.5.0") && readme.includes("v1.1.0") && readme.includes("v0.6.0") && readme.includes("not yet published"), "README version matrix is incomplete");
  console.log("[v06] package/release contract passed: aligned candidate versions, Node baseline, license, dist, stable Action pin, and README matrix");
}

async function runLegacyReleaseGate() {
  const result = runNode([legacyGatePath]);
  requireSuccess(result, "v0.5 compatibility gate");
  if (result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (result.stderr) {
    process.stderr.write(result.stderr);
  }
}

async function runGate() {
  assert(path.isAbsolute(cliPath), "built CLI path is not configured");
  await runLegacyReleaseGate();
  await checkDevelopmentRuleMatrix();
  checkCliSmoke();
  await checkPackageContract();
  console.log("[v06] release quality gate passed");
}

try {
  await runGate();
} catch (error) {
  console.error(`[v06] release quality gate failed: ${error instanceof Error ? error.message : "unknown error"}`);
  process.exitCode = 1;
} finally {
  await Promise.all(temporaryDirectories.map((directory) => rm(directory, { recursive: true, force: true })));
}
