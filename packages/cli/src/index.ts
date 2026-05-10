#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import { scanProject, type Severity } from "@next-secure-check/core";
import { getBuiltInRules } from "@next-secure-check/rules";
import { formatReport, type ReportFormat } from "@next-secure-check/reporter";

const program = new Command();

program
  .name("next-secure-check")
  .description("Deterministic security checks for Next.js projects.")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a project directory.")
  .argument("[path]", "Project path", ".")
  .option("--format <format>", "Output format: terminal, json, markdown, or github", "terminal")
  .option("--output <path>", "Write the report to a file")
  .option("--fail-on <severity>", "Exit with code 1 when findings at or above severity exist")
  .option("--category <categories>", "Comma-separated categories to run, e.g. secrets,auth,xss")
  .action(async (targetPath: string, options: ScanCommandOptions) => {
    try {
      const format = parseFormat(options.format);
      const result = await scanProject(targetPath, {
        categories: parseCategories(options.category),
        rules: getBuiltInRules(),
        toolVersion: program.version()
      });
      const output = formatReport(result, format);

      if (options.output) {
        await writeFile(options.output, output, "utf8");
      } else {
        console.log(output);
      }

      if (shouldFail(result.findings.map((finding) => finding.severity), options.failOn)) {
        process.exitCode = 1;
      }
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

program.parse();

type ScanCommandOptions = {
  format: string;
  output?: string;
  failOn?: string;
  category?: string;
};

function parseFormat(format: string): ReportFormat {
  if (["terminal", "json", "markdown", "github"].includes(format)) {
    return format as ReportFormat;
  }

  throw new Error(`Unsupported output format: ${format}`);
}

function parseCategories(categories?: string): string[] | undefined {
  return categories
    ?.split(",")
    .map((category) => category.trim())
    .filter(Boolean);
}

function shouldFail(severities: Severity[], failOn?: string): boolean {
  if (!failOn) {
    return false;
  }

  const threshold = severityRank(parseSeverity(failOn));
  return severities.some((severity) => severityRank(severity) >= threshold);
}

function parseSeverity(value: string): Severity {
  const normalized = value.toUpperCase();
  if (["HIGH", "MEDIUM", "LOW", "INFO"].includes(normalized)) {
    return normalized as Severity;
  }

  throw new Error(`Unsupported fail-on severity: ${value}`);
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "HIGH":
      return 3;
    case "MEDIUM":
      return 2;
    case "LOW":
      return 1;
    case "INFO":
      return 0;
  }
}
