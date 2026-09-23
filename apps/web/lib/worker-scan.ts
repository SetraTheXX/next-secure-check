import { Worker } from "node:worker_threads";
import type { ScanResult } from "@next-secure-check/core";
import { OperationTimeoutError } from "./timeout";

export type ScanWorkerOptions = {
  excludePaths?: string[];
  maxFiles?: number;
  maxTotalBytes?: number;
};

type WorkerMessage<T> =
  | { type: "started" }
  | { type: "result"; result: T }
  | { type: "error"; error: { message: string; name?: string } };

export type ScanWorkerImpl = (
  rootPath: string,
  options: ScanWorkerOptions,
  timeoutMs: number
) => Promise<ScanResult>;

export function scanProjectInWorker(
  rootPath: string,
  options: ScanWorkerOptions,
  timeoutMs: number
): Promise<ScanResult> {
  const worker = new Worker(new URL("./scan-worker.mjs", import.meta.url), {
    workerData: { rootPath, options }
  });

  return runWorkerUntilTimeout<ScanResult>(worker, timeoutMs);
}

export function runWorkerUntilTimeout<T>(worker: Worker, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;

    const cleanupListeners = () => {
      clearTimeout(timeout);
      worker.off("message", onMessage);
      worker.off("error", onError);
      worker.off("exit", onExit);
    };

    const finish = async (error?: unknown, result?: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      try {
        await worker.terminate();
      } catch (terminationError) {
        error = terminationError;
      }
      cleanupListeners();
      if (error !== undefined) reject(error);
      else resolve(result as T);
    };

    const onMessage = (message: WorkerMessage<T>) => {
      if (message.type === "started") return;
      if (message.type === "result") {
        void finish(undefined, message.result);
        return;
      }

      const error = new Error(message.error.message);
      error.name = message.error.name ?? "Error";
      void finish(error);
    };

    const onError = (error: Error) => {
      void finish(error);
    };

    const onExit = (code: number) => {
      if (!settled) {
        void finish(new Error(`Scan worker exited before returning a result (code ${code})`));
      }
    };

    worker.on("message", onMessage);
    worker.on("error", onError);
    worker.on("exit", onExit);
    const timeout = setTimeout(() => {
      void finish(new OperationTimeoutError("Repository scan timed out"));
    }, timeoutMs);
  });
}
