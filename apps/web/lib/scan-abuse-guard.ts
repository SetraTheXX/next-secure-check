const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_SCANS_PER_WINDOW = 3;
const MAX_ACTIVE_SCANS = 2;

type RateLimitBucket = {
  count: number;
  windowStartMs: number;
};

export type ScanAbuseGuardResult =
  | {
      ok: true;
      release: () => void;
    }
  | {
      ok: false;
      code: "SCAN_RATE_LIMITED" | "CONCURRENT_SCAN_LIMIT_EXCEEDED";
      message: string;
    };

const rateLimitBuckets = new Map<string, RateLimitBucket>();
let activeScans = 0;

export function getScanClientIp(headers: Headers): string {
  const forwardedFor = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (forwardedFor) {
    return forwardedFor;
  }

  const realIp = headers.get("x-real-ip")?.trim();
  if (realIp) {
    return realIp;
  }

  return "unknown";
}

export function tryAcquireScanSlot(ip: string, nowMs = Date.now()): ScanAbuseGuardResult {
  const bucket = getRateLimitBucket(ip, nowMs);
  if (bucket.count >= MAX_SCANS_PER_WINDOW) {
    return {
      ok: false,
      code: "SCAN_RATE_LIMITED",
      message: "Too many scan requests. Please wait before starting another scan."
    };
  }

  if (activeScans >= MAX_ACTIVE_SCANS) {
    return {
      ok: false,
      code: "CONCURRENT_SCAN_LIMIT_EXCEEDED",
      message: "Too many scans are running. Please try again shortly."
    };
  }

  bucket.count += 1;
  activeScans += 1;

  let released = false;
  return {
    ok: true,
    release: () => {
      if (released) {
        return;
      }

      released = true;
      activeScans = Math.max(0, activeScans - 1);
    }
  };
}

export function resetScanAbuseGuardForTests(): void {
  rateLimitBuckets.clear();
  activeScans = 0;
}

function getRateLimitBucket(ip: string, nowMs: number): RateLimitBucket {
  const current = rateLimitBuckets.get(ip);
  if (!current || nowMs - current.windowStartMs >= RATE_LIMIT_WINDOW_MS) {
    const next = {
      count: 0,
      windowStartMs: nowMs
    };
    rateLimitBuckets.set(ip, next);
    return next;
  }

  return current;
}
