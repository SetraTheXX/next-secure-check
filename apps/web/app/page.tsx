"use client";

import { FormEvent, useMemo, useState } from "react";
import {
  createScanJsonExport,
  createScanMarkdownExport,
  formatFindingLocation,
  LOADING_STATE_TITLE,
  validateRepoInput,
  type ScanApiFinding,
  type ScanApiResult,
  type ScanApiSuccess,
  type ScanStatus
} from "../lib/scan-ui";

export default function Home() {
  const [input, setInput] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanApiSuccess | null>(null);
  const [status, setStatus] = useState<ScanStatus>("idle");

  const validationError = useMemo(() => {
    if (!input.trim()) {
      return null;
    }
    return validateRepoInput(input);
  }, [input]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const error = validateRepoInput(input);
    if (error) {
      setSubmitError(error);
      setScanError(null);
      setResult(null);
      setStatus("idle");
      return;
    }

    setStatus("loading");
    setSubmitError(null);
    setScanError(null);
    setResult(null);

    try {
      const response = await fetch("/api/scans", {
        body: JSON.stringify({ repoUrl: input.trim() }),
        headers: {
          "Content-Type": "application/json"
        },
        method: "POST"
      });
      const data = (await response.json()) as ScanApiResult;

      if (!response.ok || !data.ok) {
        setScanError(data.ok ? "Scan failed." : data.message);
        setStatus("error");
        return;
      }

      setResult(data);
      setStatus("success");
    } catch {
      setScanError("Scan request failed. Please try again.");
      setStatus("error");
    }
  }

  return (
    <main className="scan-shell">
      <section className="scan-panel" aria-labelledby="scan-title">
        <header className="header">
          <div>
            <p className="eyebrow">Rule-based static scanner</p>
            <h1 id="scan-title">next-secure-check Web Demo</h1>
          </div>
          <div className="status-pill">Public repos only</div>
        </header>

        <form className="form" onSubmit={handleSubmit}>
          <label htmlFor="repo-url">GitHub repository URL</label>
          <div className="input-row">
            <input
              id="repo-url"
              type="url"
              placeholder="https://github.com/owner/repo"
              autoComplete="off"
              value={input}
              onChange={(event) => {
                setInput(event.target.value);
                setSubmitError(null);
              }}
            />
            <button type="submit" disabled={status === "loading" || Boolean(validationError)}>
              {status === "loading" ? "Scanning..." : "Scan"}
            </button>
          </div>
          {validationError ? <div className="validation error">{validationError}</div> : null}
          {submitError ? <div className="validation error">{submitError}</div> : null}
        </form>

        {status === "loading" ? <LoadingState /> : null}
        {scanError ? <ErrorState message={scanError} /> : null}
        {result ? <ScanResultView result={result} /> : null}

        <div className="note">No repo scripts are executed. Evidence for secret findings is redacted.</div>
      </section>
    </main>
  );
}

function LoadingState() {
  return (
    <section className="state-panel" aria-live="polite">
      <div className="spinner" aria-hidden="true" />
      <div>
        <h2>{LOADING_STATE_TITLE}</h2>
        <p>Downloading, extracting, running deterministic rules, and cleaning up.</p>
      </div>
    </section>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <section className="state-panel error-panel" role="alert">
      <h2>Scan could not complete</h2>
      <p>{message}</p>
    </section>
  );
}

function ScanResultView({ result }: { result: ScanApiSuccess }) {
  const summary = result.scan.summary;
  const [copiedFormat, setCopiedFormat] = useState<"json" | "markdown" | null>(null);

  async function copyExport(format: "json" | "markdown") {
    const content =
      format === "json" ? createScanJsonExport(result) : createScanMarkdownExport(result);
    await navigator.clipboard.writeText(content);
    setCopiedFormat(format);
  }

  return (
    <section className="results" aria-label="Scan results">
      <div className="result-topline">
        <div>
          <p className="eyebrow">Scan complete</p>
          <h2>
            <a href={result.repo.htmlUrl} target="_blank" rel="noreferrer">
              {result.repo.fullName}
            </a>
          </h2>
        </div>
        <div className={`risk-badge risk-${summary.riskLevel}`}>{summary.riskLevel}</div>
      </div>

      <div className="metric-grid">
        <Metric label="Score" value={summary.score} />
        <Metric label="Findings" value={summary.totalFindings} />
        <Metric label="High" value={summary.high} tone="high" />
        <Metric label="Medium" value={summary.medium} tone="medium" />
        <Metric label="Low" value={summary.low} tone="low" />
        <Metric label="Info" value={summary.info} />
      </div>

      <div className="repo-meta">
        <span>Branch: {result.repo.defaultBranch}</span>
        <span>Files extracted: {result.extraction.fileCount}</span>
        <span>Bytes: {result.extraction.totalBytes}</span>
      </div>

      <div className="export-actions" aria-label="Export scan result">
        <button type="button" onClick={() => void copyExport("json")}>
          {copiedFormat === "json" ? "JSON copied" : "Copy JSON"}
        </button>
        <button type="button" onClick={() => void copyExport("markdown")}>
          {copiedFormat === "markdown" ? "Markdown copied" : "Copy Markdown"}
        </button>
      </div>

      <div className="findings">
        <h3>Findings</h3>
        {result.scan.findings.length === 0 ? (
          <p className="empty-findings">No findings returned by the selected rules.</p>
        ) : (
          <ul>
            {result.scan.findings.map((finding) => (
              <li key={finding.id} className="finding-item">
                <div className="finding-header">
                  <div>
                    <h4>{finding.title}</h4>
                    <p>{finding.ruleId}</p>
                  </div>
                  <div className="finding-badges">
                    <span className={`severity severity-${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                    <span>{finding.confidence}</span>
                  </div>
                </div>
                <div className="location">{formatFindingLocation(finding)}</div>
                {finding.evidence ? <pre className="evidence">{finding.evidence}</pre> : null}
                <p className="recommendation">{finding.recommendation}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function Metric({
  label,
  tone,
  value
}: {
  label: string;
  tone?: "high" | "medium" | "low";
  value: number;
}) {
  return (
    <div className={`metric ${tone ? `metric-${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
