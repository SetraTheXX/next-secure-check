#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import { scanProject } from "@next-secure-check/core";
import { getBuiltInRules } from "@next-secure-check/rules";
import { formatReport } from "@next-secure-check/reporter";
import { resolveScanCommandSettings, type ScanCommandOptions } from "./config.js";
import { shouldFail } from "./fail-on.js";
import { formatRuleExplanation, formatRulesList, formatUnknownRuleMessage } from "./rules-info.js";

const program = new Command();

program
  .name("next-secure-check")
  .description("Deterministic security checks for Next.js projects.")
  .version("0.2.1");

program
  .command("scan")
  .description("Scan a project directory.")
  .argument("[path]", "Project path", ".")
  .option("--format <format>", "Output format: terminal, json, markdown, github, or sarif")
  .option("--output <path>", "Write the report to a file")
  .option("--fail-on <level>", "Exit with code 1 on severity threshold, or critical risk level")
  .option("--category <categories>", "Comma-separated categories to run, e.g. secrets,auth,xss")
  .option("--exclude <patterns>", "Comma-separated relative path globs to exclude, e.g. **/*.test.ts,examples/**")
  .option("--preset <preset>", "Scan preset: default, app, strict, ci, audit, library, or monorepo")
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
        contextTuning: settings.contextTuning,
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

program
  .command("rules")
  .description("List built-in security rules.")
  .action(() => {
    console.log(formatRulesList(getBuiltInRules()));
  });

program
  .command("explain")
  .description("Explain a built-in security rule.")
  .argument("<rule-id>", "Rule id, e.g. xss/dangerously-set-inner-html")
  .action((ruleId: string) => {
    const rules = getBuiltInRules();
    const explanation = formatRuleExplanation(rules, ruleId);

    if (!explanation) {
      console.error(formatUnknownRuleMessage(rules, ruleId));
      process.exitCode = 1;
      return;
    }

    console.log(explanation);
  });

program.parse();
