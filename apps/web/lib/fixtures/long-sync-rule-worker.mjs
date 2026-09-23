import { parentPort, workerData } from "node:worker_threads";
import { scanProject } from "@next-secure-check/core";

const blockingRule = {
  category: "test",
  id: "test/long-sync-rule",
  scan: () => {
    parentPort?.postMessage({ type: "started" });
    const deadline = Date.now() + workerData.blockMs;
    while (Date.now() < deadline) {
      // Reproduce a synchronous rule that prevents its own event loop from running.
    }
    return [];
  },
  severity: "LOW",
  title: "Long synchronous test rule"
};

try {
  const result = await scanProject(workerData.rootPath, { rules: [blockingRule] });
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
