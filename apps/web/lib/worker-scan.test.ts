import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { describe, expect, it } from "vitest";
import { OperationTimeoutError } from "./timeout";
import { runWorkerUntilTimeout, scanProjectInWorker } from "./worker-scan";

describe("scan workers", () => {
  it("terminates a worker while a synchronous scan rule is still running", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "next-secure-check-worker-test-"));
    await writeFile(path.join(root, "index.ts"), "export {};\n");
    const worker = new Worker(new URL("./fixtures/long-sync-rule-worker.mjs", import.meta.url), {
      workerData: { blockMs: 5_000, rootPath: root }
    });

    try {
      await new Promise<void>((resolve, reject) => {
        worker.once("message", (message: { type?: string }) => {
          if (message.type === "started") resolve();
          else reject(new Error("The synchronous test rule did not start"));
        });
        worker.once("error", reject);
      });

      const startedAt = Date.now();
      await expect(runWorkerUntilTimeout(worker, 25)).rejects.toBeInstanceOf(OperationTimeoutError);

      expect(Date.now() - startedAt).toBeLessThan(3_000);
    } finally {
      await worker.terminate();
      await rm(root, { force: true, recursive: true });
    }
  });

  it("runs a normal scan in the isolated worker", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "next-secure-check-worker-test-"));
    await writeFile(path.join(root, "package.json"), '{"dependencies":{"next":"16.3.3"}}\n');

    try {
      await expect(scanProjectInWorker(root, {}, 5_000)).resolves.toMatchObject({
        findings: expect.any(Array),
        project: expect.objectContaining({ framework: "nextjs" })
      });
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });
});
