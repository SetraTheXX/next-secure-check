type SafeScanLogEvent = {
  code?: string;
  durationMs: number;
  event: "scan_completed" | "scan_rejected" | "scan_failed";
  scanId: string;
  status: number;
};

export function logSafeScanEvent(event: SafeScanLogEvent): void {
  const payload = {
    code: event.code,
    durationMs: event.durationMs,
    event: event.event,
    scanId: event.scanId,
    status: event.status
  };

  if (event.status >= 500) {
    console.warn(payload);
    return;
  }

  console.info(payload);
}
