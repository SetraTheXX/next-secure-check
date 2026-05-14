"use client";

import { useMemo, useState } from "react";
import { parseGitHubRepoUrl } from "../lib/github-url";

export default function Home() {
  const [input, setInput] = useState("");
  const result = useMemo(() => {
    if (!input.trim()) {
      return null;
    }
    return parseGitHubRepoUrl(input);
  }, [input]);

  return (
    <main className="card">
      <header className="header">
        <h1>next-secure-check Web Demo</h1>
        <p className="subtitle">
          Public GitHub repo URL ile statik guvenlik taramasi.
        </p>
      </header>

      <div className="form">
        <label htmlFor="repo-url">Public GitHub repo URL</label>
        <input
          id="repo-url"
          type="url"
          placeholder="https://github.com/owner/repo"
          autoComplete="off"
          value={input}
          onChange={(event) => setInput(event.target.value)}
        />
        {result && !result.ok ? (
          <div className="validation error">{result.error}</div>
        ) : null}
        <button type="button" disabled>
          Scan (coming soon)
        </button>
      </div>

      <div className="note">
        Only public repositories. No code execution. No npm install.
      </div>
    </main>
  );
}
