export const RATE_LIMIT_WINDOW_MS = 60_000;
export const MAX_SCANS_PER_WINDOW = 3;
export const MAX_ACTIVE_SCANS = 2;

export type ScanSlotAcquireResult =
  | {
      ok: true;
      release: () => Promise<void> | void;
    }
  | {
      ok: false;
      code: "SCAN_RATE_LIMITED" | "CONCURRENT_SCAN_LIMIT_EXCEEDED";
      message: string;
    };

export interface ScanAbuseStore {
  acquire(ip: string, nowMs: number): Promise<ScanSlotAcquireResult> | ScanSlotAcquireResult;
  resetForTests?(): void;
}

type RateLimitBucket = {
  count: number;
  windowStartMs: number;
};

export class InMemoryScanAbuseStore implements ScanAbuseStore {
  private readonly rateLimitBuckets = new Map<string, RateLimitBucket>();
  private activeScans = 0;

  acquire(ip: string, nowMs: number): ScanSlotAcquireResult {
    const bucket = this.getRateLimitBucket(ip, nowMs);
    if (bucket.count >= MAX_SCANS_PER_WINDOW) {
      return rateLimitedResult();
    }

    if (this.activeScans >= MAX_ACTIVE_SCANS) {
      return concurrentLimitResult();
    }

    bucket.count += 1;
    this.activeScans += 1;

    let released = false;
    return {
      ok: true,
      release: () => {
        if (released) {
          return;
        }

        released = true;
        this.activeScans = Math.max(0, this.activeScans - 1);
      }
    };
  }

  resetForTests(): void {
    this.rateLimitBuckets.clear();
    this.activeScans = 0;
  }

  private getRateLimitBucket(ip: string, nowMs: number): RateLimitBucket {
    const current = this.rateLimitBuckets.get(ip);
    if (!current || nowMs - current.windowStartMs >= RATE_LIMIT_WINDOW_MS) {
      const next = {
        count: 0,
        windowStartMs: nowMs
      };
      this.rateLimitBuckets.set(ip, next);
      return next;
    }

    return current;
  }
}

export function rateLimitedResult(): ScanSlotAcquireResult {
  return {
    ok: false,
    code: "SCAN_RATE_LIMITED",
    message: "Too many scan requests. Please wait before starting another scan."
  };
}

export function concurrentLimitResult(): ScanSlotAcquireResult {
  return {
    ok: false,
    code: "CONCURRENT_SCAN_LIMIT_EXCEEDED",
    message: "Too many scans are running. Please try again shortly."
  };
}
