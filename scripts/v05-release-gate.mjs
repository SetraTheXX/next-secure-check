import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const scriptPath = fileURLToPath(import.meta.url);
const cliPath = path.join(repoRoot, "packages", "cli", "dist", "index.js");
const pnpmCommand = process.platform === "win32" ? "pnpm.cmd" : "pnpm";

const FIXTURES = [
  {
    name: "vulnerable",
    target: "examples/vulnerable-next-app",
    preset: "strict",
    expected: { score: 0, riskLevel: "critical", totalFindings: 26, high: 12, medium: 11, low: 2, info: 1 },
  },
  {
    name: "secure",
    target: "examples/secure-next-app",
    preset: "app",
    expected: { score: 99, riskLevel: "excellent", totalFindings: 1, high: 0, medium: 0, low: 1, info: 0 },
  },
  {
    name: "self",
    target: ".",
    preset: "app",
    expected: { score: 100, riskLevel: "excellent", totalFindings: 0, high: 0, medium: 0, low: 0, info: 0 },
  },
];

const EXPECTED_INVENTORIES = {
  vulnerable: {
    "auth/admin-route-without-auth|api-code|HIGH|MEDIUM": 1,
    "auth/login-without-rate-limit|api-code|HIGH|MEDIUM": 1,
    "auth/password-without-hashing-library|api-code|MEDIUM|MEDIUM": 1,
    "auth/register-without-rate-limit|api-code|HIGH|MEDIUM": 1,
    "config/insecure-cors-wildcard|api-code|MEDIUM|HIGH": 1,
    "config/next-powered-by-header|unknown|INFO|MEDIUM": 1,
    "config/production-browser-source-maps|unknown|LOW|HIGH": 1,
    "headers/missing-security-headers|unknown|LOW|LOW": 1,
    "injection/command-exec|api-code|HIGH|MEDIUM": 2,
    "injection/no-eval|api-code|HIGH|HIGH": 1,
    "injection/no-new-function|api-code|HIGH|HIGH": 1,
    "injection/raw-sql-concat|api-code|HIGH|MEDIUM": 1,
    "secrets/hardcoded-secret|api-code|HIGH|HIGH": 1,
    "secrets/hardcoded-secret|unknown|HIGH|MEDIUM": 1,
    "secrets/next-public-secret|unknown|HIGH|MEDIUM": 1,
    "secrets/weak-jwt-secret|api-code|HIGH|HIGH": 1,
    "upload/missing-file-size-limit|api-code|MEDIUM|MEDIUM": 1,
    "upload/missing-file-type-validation|api-code|MEDIUM|MEDIUM": 1,
    "validation/api-route-without-validation|api-code|MEDIUM|MEDIUM": 6,
    "xss/dangerously-set-inner-html|app-code|MEDIUM|HIGH": 1
  },
  secure: {
    "headers/missing-security-headers|unknown|LOW|LOW": 1
  },
  self: {}
};

const BENCHMARK_SAMPLES = 9;
const BENCHMARKS = [
  { name: "small", files: 100, coldScannerP95Ms: 2_000, coldProcessP95Ms: 4_000, warmP95Ms: 2_000 },
  { name: "medium", files: 1_000, coldScannerP95Ms: 8_000, coldProcessP95Ms: 10_000, warmP95Ms: 8_000 },
];
const MAX_SUMMARY_LINES = 14;
const MAX_WARM_SCALING_RATIO = 20;
const MAX_ANALYSIS_OVERHEAD_RATIO = 20;
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

function percentile(values, quantile) {
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * quantile) - 1));
  return sorted[index];
}

function statistics(values) {
  return {
    median: percentile(values, 0.5),
    p95: percentile(values, 0.95),
  };
}

function roundMilliseconds(value) {
  return Number(value.toFixed(1));
}

const WINDOWS_ABSOLUTE_PATH = /(?:^|[^A-Za-z0-9])(?:[A-Za-z]:[\\/]|\\\\[A-Za-z0-9])/;
const POSIX_ABSOLUTE_PATH = /\/(?:Users|home|runner|tmp|workspace)\//;
const CREDENTIAL_TOKEN = /\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_(?:live|test)_[A-Za-z0-9_-]{16,})\b/;

function assertPublicOutput(text, label, privateMarker = "") {
  assert(!WINDOWS_ABSOLUTE_PATH.test(text), `${label} leaked an absolute Windows path`);
  assert(!POSIX_ABSOLUTE_PATH.test(text), `${label} leaked an absolute POSIX path`);
  assert(!CREDENTIAL_TOKEN.test(text), `${label} leaked a credential-shaped token`);
  if (privateMarker) {
    assert(!text.includes(privateMarker), `${label} leaked the privacy fixture marker`);
  }
}

function summaryLineCount(text) {
  const trimmed = text.trimEnd();
  return trimmed ? trimmed.split(/\r?\n/).length : 0;
}

function assertExpectedSummary(summary, expected, label) {
  for (const key of Object.keys(expected)) {
    assert(summary?.[key] === expected[key], `${label} changed ${key}: expected ${expected[key]}, received ${summary?.[key]}`);
  }
}

function findingInventory(findings) {
  const inventory = new Map();
  for (const finding of findings) {
    const key = [finding.ruleId, finding.context ?? "unknown", finding.severity, finding.confidence].join("|");
    inventory.set(key, (inventory.get(key) ?? 0) + 1);
  }
  return Object.fromEntries([...inventory.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

async function makeTemporaryDirectory(prefix) {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

async function checkFixtureContracts() {
  for (const fixture of FIXTURES) {
    const jsonOptions = ["--preset", fixture.preset, "--format", "json"];
    const first = runCli(fixture.target, jsonOptions);
    const second = runCli(fixture.target, jsonOptions);
    requireSuccess(first, `${fixture.name} JSON scan`);
    requireSuccess(second, `${fixture.name} repeated JSON scan`);

    const firstReport = parseJson(first.stdout, `${fixture.name} JSON scan`);
    const secondReport = parseJson(second.stdout, `${fixture.name} repeated JSON scan`);
    assertExpectedSummary(firstReport.summary, fixture.expected, `${fixture.name} fixture`);
    assert(stableJson(findingInventory(firstReport.findings)) === stableJson(EXPECTED_INVENTORIES[fixture.name]), `${fixture.name} finding inventory changed`);
    assert(stableJson(withoutVolatileMetadata(firstReport)) === stableJson(withoutVolatileMetadata(secondReport)), `${fixture.name} JSON report is not deterministic`);
    assertPublicOutput(first.stdout, `${fixture.name} JSON`);

    const summary = runCli(fixture.target, ["--preset", fixture.preset, "--summary"]);
    requireSuccess(summary, `${fixture.name} summary scan`);
    assert(summaryLineCount(summary.stdout) <= MAX_SUMMARY_LINES, `${fixture.name} summary has ${summaryLineCount(summary.stdout)} lines; maximum is ${MAX_SUMMARY_LINES}`);
    assertPublicOutput(summary.stdout, `${fixture.name} summary`);
  }

  const help = runNode([cliPath, "scan", "--help"]);
  requireSuccess(help, "scan help");
  assert(help.stdout.includes("--summary"), "scan help does not document --summary");

  const incompatible = runCli("examples/secure-next-app", ["--format", "json", "--summary"]);
  assert(incompatible.status !== 0, "JSON plus --summary should be rejected");
}

async function checkSarifContract() {
  const options = ["--preset", "strict", "--format", "sarif"];
  const first = runCli("examples/vulnerable-next-app", options);
  const second = runCli("examples/vulnerable-next-app", options);
  requireSuccess(first, "vulnerable SARIF scan");
  requireSuccess(second, "repeated vulnerable SARIF scan");

  const firstReport = parseJson(first.stdout, "vulnerable SARIF scan");
  const secondReport = parseJson(second.stdout, "repeated vulnerable SARIF scan");
  const firstRun = firstReport.runs?.[0];
  const secondRun = secondReport.runs?.[0];
  const results = firstRun?.results ?? [];
  assert(firstReport.version === "2.1.0", "SARIF version is not 2.1.0");
  assert(firstReport.runs?.length === 1 && secondReport.runs?.length === 1, "SARIF must contain exactly one run");
  assert(results.length === 26, `SARIF result count changed: expected 26, received ${results.length}`);
  assert(new Set(results.map((result) => result.ruleId)).size === 19, "SARIF rule identity count changed: expected 19");
  assert(results.every((result) => Object.keys(result.partialFingerprints ?? {}).length > 0), "SARIF result is missing a partial fingerprint");
  assert(stableJson(firstReport) === stableJson(secondReport), "SARIF report is not deterministic");
  assertPublicOutput(first.stdout, "vulnerable SARIF");
  assert(secondRun?.results?.length === results.length, "repeated SARIF result count changed");
}

async function checkPrivacyContract() {
  const directory = await makeTemporaryDirectory("next-secure-check-v05-privacy-");
  const marker = "gate-sensitive-marker-0123456789";
  const configDirectory = path.join(directory, "config");
  await mkdir(configDirectory, { recursive: true });
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ name: "privacy-fixture", dependencies: { next: "16.3.2" } }));
  await writeFile(path.join(configDirectory, "secrets.ts"), `export const STRIPE_KEY = "sk_live_${marker}";\n`);

  const target = path.relative(repoRoot, directory);
  for (const format of ["json", "markdown", "github", "sarif"]) {
    const result = runCli(target, ["--preset", "strict", "--format", format]);
    requireSuccess(result, `privacy ${format} scan`);
    assertPublicOutput(result.stdout, `privacy ${format}`, marker);
    if (format === "json") {
      const report = parseJson(result.stdout, "privacy JSON scan");
      assert(report.findings?.length > 0, "privacy fixture did not produce a finding to redact");
    }
  }
}

async function checkPackContract() {
  const result = runCommand(pnpmCommand, ["-C", "packages/cli", "exec", "npm", "pack", "--dry-run"], {
    shell: process.platform === "win32"
  });
  requireSuccess(result, "CLI npm pack dry-run");
  assert(result.stdout.includes("next-secure-check"), "CLI npm pack dry-run did not report the package");
}

function benchmarkFileContents(index) {
  const variant = index % 4;
  if (variant === 0) {
    return `export const value${index} = ${index};\n`;
  }
  if (variant === 1) {
    return `export function read${index}() { return ${index}; }\n`;
  }
  if (variant === 2) {
    return `const values${index} = [${index}, ${index + 1}, ${index + 2}];\nexport { values${index} };\n`;
  }
  return `export const label${index} = "fixture-${index}";\n`;
}

async function makeBenchmarkCorpus(fileCount) {
  const directory = await makeTemporaryDirectory(`next-secure-check-v05-${fileCount}-`);
  await Promise.all(
    Array.from({ length: fileCount }, (_, index) => writeFile(path.join(directory, `fixture-${index}.ts`), benchmarkFileContents(index))),
  );
  return directory;
}

async function loadScanner() {
  const [core, rules] = await Promise.all([
    import(pathToFileURL(path.join(repoRoot, "packages", "core", "dist", "index.js")).href),
    import(pathToFileURL(path.join(repoRoot, "packages", "rules", "dist", "index.js")).href),
  ]);
  return { scanProject: core.scanProject, getBuiltInRules: rules.getBuiltInRules };
}

async function scanInProcess(scanProject, corpus, rules) {
  const started = performance.now();
  const result = await scanProject(corpus, { rules });
  return { elapsedMs: performance.now() - started, findings: result.findings.length };
}

function scanInFreshProcess(corpus) {
  const started = performance.now();
  const result = runNode([scriptPath, "--benchmark-worker", corpus]);
  const processMs = performance.now() - started;
  assert(result.status === 0, `cold benchmark worker failed for ${corpus}`);
  const payload = parseJson(result.stdout, "cold benchmark worker");
  assert(payload.findings === 0, `benchmark corpus produced ${payload.findings} findings`);
  return { scannerMs: payload.scannerMs, processMs };
}

async function runBenchmark(benchmark, scanner) {
  const corpus = await makeBenchmarkCorpus(benchmark.files);
  const fullRules = scanner.getBuiltInRules();
  const coldScanner = [];
  const coldProcess = [];
  const warm = [];
  const baseline = [];

  try {
    for (let index = 0; index < BENCHMARK_SAMPLES; index += 1) {
      const cold = scanInFreshProcess(corpus);
      coldScanner.push(cold.scannerMs);
      coldProcess.push(cold.processMs);
    }
    for (let index = 0; index < BENCHMARK_SAMPLES; index += 1) {
      const full = await scanInProcess(scanner.scanProject, corpus, fullRules);
      assert(full.findings === 0, `warm benchmark produced ${full.findings} findings`);
      warm.push(full.elapsedMs);
      const noRules = await scanInProcess(scanner.scanProject, corpus, []);
      assert(noRules.findings === 0, `no-rule benchmark produced ${noRules.findings} findings`);
      baseline.push(noRules.elapsedMs);
    }
  } finally {
    await rm(corpus, { recursive: true, force: true });
    const position = temporaryDirectories.indexOf(corpus);
    if (position >= 0) {
      temporaryDirectories.splice(position, 1);
    }
  }

  const stats = {
    coldScanner: statistics(coldScanner),
    coldProcess: statistics(coldProcess),
    warm: statistics(warm),
    baseline: statistics(baseline),
  };
  assert(stats.coldScanner.p95 <= benchmark.coldScannerP95Ms, `${benchmark.name} cold scanner p95 exceeded ${benchmark.coldScannerP95Ms}ms`);
  assert(stats.coldProcess.p95 <= benchmark.coldProcessP95Ms, `${benchmark.name} cold process p95 exceeded ${benchmark.coldProcessP95Ms}ms`);
  assert(stats.warm.p95 <= benchmark.warmP95Ms, `${benchmark.name} warm p95 exceeded ${benchmark.warmP95Ms}ms`);
  const analysisOverheadRatio = stats.warm.median / Math.max(stats.baseline.median, 5);
  assert(analysisOverheadRatio <= MAX_ANALYSIS_OVERHEAD_RATIO, `${benchmark.name} analysis overhead ratio ${analysisOverheadRatio.toFixed(2)} exceeded ${MAX_ANALYSIS_OVERHEAD_RATIO}x`);

  return { ...benchmark, stats, analysisOverheadRatio };
}

async function checkBenchmarks() {
  const scanner = await loadScanner();
  const results = [];
  for (const benchmark of BENCHMARKS) {
    results.push(await runBenchmark(benchmark, scanner));
  }

  const small = results.find((result) => result.name === "small");
  const medium = results.find((result) => result.name === "medium");
  const warmScalingRatio = medium.stats.warm.median / Math.max(small.stats.warm.median, 5);
  assert(warmScalingRatio <= MAX_WARM_SCALING_RATIO, `warm corpus scaling ratio ${warmScalingRatio.toFixed(2)} exceeded ${MAX_WARM_SCALING_RATIO}x`);
  return { results, warmScalingRatio };
}

function printBenchmarkResult(result) {
  const { stats } = result;
  console.log(
    `[v05] ${result.name}: ${result.files} files; cold scanner median/p95 ${roundMilliseconds(stats.coldScanner.median)}/${roundMilliseconds(stats.coldScanner.p95)}ms; ` +
      `cold process median/p95 ${roundMilliseconds(stats.coldProcess.median)}/${roundMilliseconds(stats.coldProcess.p95)}ms; ` +
      `warm median/p95 ${roundMilliseconds(stats.warm.median)}/${roundMilliseconds(stats.warm.p95)}ms; ` +
      `analysis overhead ${result.analysisOverheadRatio.toFixed(2)}x`,
  );
}

async function runGate() {
  assert(cliPath && path.isAbsolute(cliPath), "built CLI path is not configured");
  await checkFixtureContracts();
  await checkSarifContract();
  await checkPrivacyContract();
  await checkPackContract();
  const benchmark = await checkBenchmarks();

  console.log("[v05] fixture, summary, help, determinism, SARIF, privacy, and pack checks passed");
  for (const result of benchmark.results) {
    printBenchmarkResult(result);
  }
  console.log(`[v05] warm corpus scaling ratio: ${benchmark.warmScalingRatio.toFixed(2)}x`);
  console.log("[v05] release gate passed");
}

async function runBenchmarkWorker(corpus) {
  assert(corpus, "benchmark worker corpus is missing");
  const scanner = await loadScanner();
  const result = await scanInProcess(scanner.scanProject, corpus, scanner.getBuiltInRules());
  console.log(JSON.stringify({ scannerMs: result.elapsedMs, findings: result.findings }));
}

try {
  if (process.argv[2] === "--benchmark-worker") {
    await runBenchmarkWorker(process.argv[3]);
  } else {
    await runGate();
  }
} catch (error) {
  console.error(`[v05] release gate failed: ${error instanceof Error ? error.message : "unknown error"}`);
  process.exitCode = 1;
} finally {
  await Promise.all(temporaryDirectories.map((directory) => rm(directory, { recursive: true, force: true })));
}
