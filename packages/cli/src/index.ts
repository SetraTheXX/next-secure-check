#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import { scanProject } from "@next-secure-check/core";
import { getBuiltInRules } from "@next-secure-check/rules";
import { formatReport } from "@next-secure-check/reporter";
import { resolveScanCommandSettings, type ScanCommandOptions } from "./config.js";
import { shouldFail } from "./fail-on.js";

const program = new Command();

program
  .name("next-secure-check")
  .description("Deterministic security checks for Next.js projects.")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a project directory.")
  .argument("[path]", "Project path", ".")
  .option("--format <format>", "Output format: terminal, json, markdown, github, or sarif")
  .option("--output <path>", "Write the report to a file")
  .option("--fail-on <severity>", "Exit with code 1 when findings at or above severity exist")
  .option("--category <categories>", "Comma-separated categories to run, e.g. secrets,auth,xss")
  .option("--exclude <patterns>", "Comma-separated relative path globs to exclude, e.g. **/*.test.ts,examples/**")
  .option("--config <path>", "Read scan options from a JSON config file")
  .action(async (targetPath: string, options: ScanCommandOptions) => {
    try {
      const rules = getBuiltInRules();
      const settings = await resolveScanCommandSettings(
        targetPath,
        options,
        new Set(rules.map((rule) => rule.category))
      );
      for (const warning of settings.warnings) {
        console.error(`Warning: ${warning}`);
      }

      const result = await scanProject(targetPath, {
        categories: settings.categories,
        excludePaths: settings.excludePaths,
        rules,
        toolVersion: program.version()
      });
      const output = formatReport(result, settings.format);

      if (options.output) {
        await writeFile(options.output, output, "utf8");
      } else {
        console.log(output);
      }

      if (shouldFail(result, settings.failOn)) {
        process.exitCode = 1;
      }
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

program.parse();
