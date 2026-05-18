import {
  concurrentLimitResult,
  MAX_ACTIVE_SCANS,
  MAX_SCANS_PER_WINDOW,
  RATE_LIMIT_WINDOW_MS,
  rateLimitedResult,
  type ScanAbuseStore,
  type ScanSlotAcquireResult
} from "./scan-abuse-store";

const RATE_KEY_PREFIX = "next-secure-check:scan-rate";
const ACTIVE_SCAN_KEY = "next-secure-check:active-scans";
const RATE_LIMIT_TTL_SECONDS = Math.ceil((RATE_LIMIT_WINDOW_MS * 2) / 1000);
const ACTIVE_SCAN_TTL_SECONDS = 10 * 60;

type UpstashPipelineItem = {
  error?: unknown;
  result?: unknown;
};

export class UpstashScanAbuseStore implements ScanAbuseStore {
  constructor(
    private readonly restUrl: string,
    private readonly token: string
  ) {}

  async acquire(ip: string, nowMs: number): Promise<ScanSlotAcquireResult> {
    try {
      const rateKey = `${RATE_KEY_PREFIX}:${sanitizeKeyPart(ip)}:${Math.floor(nowMs / RATE_LIMIT_WINDOW_MS)}`;
      const rateCount = await this.incrementWithExpiry(rateKey, RATE_LIMIT_TTL_SECONDS);
      if (rateCount > MAX_SCANS_PER_WINDOW) {
        return rateLimitedResult();
      }

      const activeCount = await this.incrementWithExpiry(ACTIVE_SCAN_KEY, ACTIVE_SCAN_TTL_SECONDS);
      if (activeCount > MAX_ACTIVE_SCANS) {
        await this.decrementActiveScan();
        return concurrentLimitResult();
      }

      let released = false;
      return {
        ok: true,
        release: async () => {
          if (released) {
            return;
          }

          released = true;
          await this.decrementActiveScan();
        }
      };
    } catch {
      return concurrentLimitResult();
    }
  }

  private async incrementWithExpiry(key: string, ttlSeconds: number): Promise<number> {
    const results = await this.pipeline([
      ["INCR", key],
      ["EXPIRE", key, ttlSeconds]
    ]);
    const count = Number(results[0]?.result);
    if (!Number.isFinite(count)) {
      throw new Error("Unexpected Upstash response.");
    }

    return count;
  }

  private async decrementActiveScan(): Promise<void> {
    try {
      await this.pipeline([["DECR", ACTIVE_SCAN_KEY]]);
    } catch {
      // Releasing a slot should not mask a completed scan response.
    }
  }

  private async pipeline(commands: unknown[][]): Promise<UpstashPipelineItem[]> {
    const response = await fetch(`${this.restUrl.replace(/\/+$/, "")}/pipeline`, {
      body: JSON.stringify(commands),
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json"
      },
      method: "POST"
    });

    if (!response.ok) {
      throw new Error("Upstash request failed.");
    }

    const payload = (await response.json()) as unknown;
    if (!Array.isArray(payload) || payload.some((item) => hasPipelineError(item))) {
      throw new Error("Upstash command failed.");
    }

    return payload as UpstashPipelineItem[];
  }
}

export function createUpstashScanAbuseStoreFromEnv(env = process.env): UpstashScanAbuseStore | undefined {
  const restUrl = env.UPSTASH_REDIS_REST_URL?.trim();
  const token = env.UPSTASH_REDIS_REST_TOKEN?.trim();
  if (!restUrl || !token) {
    return undefined;
  }

  return new UpstashScanAbuseStore(restUrl, token);
}

function hasPipelineError(item: unknown): boolean {
  return typeof item === "object" && item !== null && "error" in item;
}

function sanitizeKeyPart(value: string): string {
  return value.replace(/[^A-Za-z0-9:._-]/g, "_");
}
