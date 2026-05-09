#!/usr/bin/env node
import { Command } from "commander";
import { createScanResultSkeleton } from "@next-secure-check/core";
import { formatSummary } from "@next-secure-check/reporter";

const program = new Command();

program
  .name("next-secure-check")
  .description("Deterministic security checks for Next.js projects.")
  .version("0.0.0");

program
  .command("scan")
  .description("Scan a project directory.")
  .argument("[path]", "Project path", ".")
  .option("--format <format>", "Output format: terminal or json", "terminal")
  .action((targetPath: string, options: { format: string }) => {
    const result = createScanResultSkeleton(targetPath);

    if (options.format === "json") {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    console.log(formatSummary(result));
  });

program.parse();
