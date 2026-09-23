import { isIP } from "node:net";
import {
  abuseLimiterUnavailableResult,
  InMemoryScanAbuseStore,
  type ScanSlotAcquireResult
} from "./scan-abuse-store";
import { createUpstashScanAbuseStoreFromEnv } from "./upstash-scan-abuse-store";

const MAX_IP_HEADER_LENGTH = 512;

const CLIENT_IP_HEADERS = ["x-vercel-forwarded-for", "x-forwarded-for", "x-real-ip"] as const;

export type ScanAbuseGuardResult = ScanSlotAcquireResult;

const inMemoryStore = new InMemoryScanAbuseStore();

export function getScanClientIp(headers: Headers): string {
  for (const headerName of CLIENT_IP_HEADERS) {
    const clientIp = parseClientIpHeader(headers.get(headerName));
    if (clientIp === "too-long") {
      return "unknown";
    }

    if (clientIp) {
      return clientIp;
    }
  }

  return "unknown";
}

export async function tryAcquireScanSlot(ip: string, nowMs = Date.now()): Promise<ScanAbuseGuardResult> {
  let distributedStore;
  try {
    distributedStore = createUpstashScanAbuseStoreFromEnv();
  } catch {
    return abuseLimiterUnavailableResult();
  }

  if (distributedStore) {
    try {
      return await distributedStore.acquire(ip, nowMs);
    } catch {
      return abuseLimiterUnavailableResult();
    }
  }

  if (!allowsInMemoryFallback(process.env)) {
    return abuseLimiterUnavailableResult();
  }

  return inMemoryStore.acquire(ip, nowMs);
}

export function resetScanAbuseGuardForTests(): void {
  inMemoryStore.resetForTests();
}

function allowsInMemoryFallback(env: NodeJS.ProcessEnv): boolean {
  if (env.VERCEL_ENV === "production" || env.VERCEL_ENV === "preview") {
    return false;
  }

  return env.NODE_ENV === "development" || env.NODE_ENV === "test";
}

function parseClientIpHeader(value: string | null): string | "too-long" | undefined {
  if (!value) {
    return undefined;
  }

  if (value.length > MAX_IP_HEADER_LENGTH) {
    return "too-long";
  }

  const candidates = value.split(",").map((candidate) => candidate.trim());
  return candidates.find(isValidClientIp);
}

function isValidClientIp(value: string): boolean {
  return isIP(value) !== 0;
}
