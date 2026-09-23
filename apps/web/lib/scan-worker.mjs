import { parentPort, workerData } from "node:worker_threads";
import { scanProject } from "@next-secure-check/core";
import { getBuiltInRules } from "@next-secure-check/rules";

try {
  const result = await scanProject(workerData.rootPath, {
    ...workerData.options,
    rules: getBuiltInRules()
  });

  parentPort?.postMessage({ type: "result", result });
} catch (error) {
  parentPort?.postMessage({
    type: "error",
    error: {
      message: error instanceof Error ? error.message : "Scan worker failed",
      name: error instanceof Error ? error.name : "Error"
    }
  });
} finally {
  parentPort?.close();
}
