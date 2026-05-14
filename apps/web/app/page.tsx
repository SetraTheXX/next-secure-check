export default function Home() {
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
        />
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
