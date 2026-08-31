"use client";

import { useMemo, useState } from "react";
import {
  createDemoTokens,
  inspectJwt,
  type DemoToken,
} from "@/lib/inspect-jwt";

function formatValue(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

export default function JwtInspector() {
  const demos = useMemo(() => createDemoTokens(), []);
  const [token, setToken] = useState("");
  const [redact, setRedact] = useState(true);

  const result = useMemo(
    () => inspectJwt(token, { redactSignature: redact }),
    [token, redact]
  );

  function loadDemo(demo: DemoToken) {
    setToken(demo.token);
  }

  function clear() {
    setToken("");
  }

  return (
    <div className="shell">
      <header className="masthead">
        <h1 className="brand">
          JWT <span>Glass</span>
        </h1>
        <p className="tagline">
          Peek through opaque tokens. Decode header and payload on your device —
          signatures stay redacted, and nothing is sent to a server.
        </p>
        <div className="privacy-bar">Local only · decode, never verify</div>
      </header>

      <div className="grid grid-main">
        <section className="panel" style={{ animationDelay: "0.05s" }}>
          <div className="panel-meta">Input</div>
          <h2>Paste a token</h2>
          <textarea
            className="token-input"
            spellCheck={false}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...."
            value={token}
            onChange={(e) => setToken(e.target.value)}
            aria-label="JWT input"
          />
          <div className="toolbar">
            <button type="button" className="btn" onClick={clear}>
              Clear
            </button>
            <label className="toggle">
              <input
                type="checkbox"
                checked={redact}
                onChange={(e) => setRedact(e.target.checked)}
              />
              Redact signature
            </label>
          </div>

          <div className="scan-line" aria-hidden />

          <div className="panel-meta">Synthetic examples</div>
          <h2>
            Demo tokens
            <span className="badge">DEMO</span>
          </h2>
          <p style={{ margin: "0 0 0.75rem", color: "var(--paper-faint)", fontSize: "0.8rem" }}>
            Generated in-browser. Not real credentials — for learning warnings
            and claims only.
          </p>
          <div className="demo-list">
            {demos.map((demo) => (
              <button
                key={demo.id}
                type="button"
                className="demo-card"
                onClick={() => loadDemo(demo)}
              >
                <strong>
                  {demo.label}
                  <span className="badge">{demo.badge}</span>
                </strong>
                <p>{demo.description}</p>
              </button>
            ))}
          </div>
        </section>

        <section className="panel" style={{ animationDelay: "0.12s" }}>
          <div className="panel-meta">Inspection</div>
          <h2>Findings</h2>

          {result.raw ? (
            <p className="display-token" title="Display form of token">
              {result.displayToken}
              <br />
              <span style={{ opacity: 0.7 }}>
                {result.sizeBytes} bytes · {result.ok ? "decoded" : "incomplete"}
              </span>
            </p>
          ) : null}

          {result.warnings.length > 0 ? (
            <div className="warnings" role="status">
              {result.warnings.map((w) => (
                <div key={w.code + w.message} className={`warning ${w.severity}`}>
                  <strong>{w.severity.toUpperCase()}</strong> — {w.message}
                </div>
              ))}
            </div>
          ) : null}

          {result.ok ? (
            <>
              <div className="split split-2" style={{ marginBottom: "1.25rem" }}>
                <div>
                  <div className="panel-meta">Header</div>
                  <pre className="json-block">
                    {JSON.stringify(result.header, null, 2)}
                  </pre>
                </div>
                <div>
                  <div className="panel-meta">Payload</div>
                  <pre className="json-block">
                    {JSON.stringify(result.payload, null, 2)}
                  </pre>
                </div>
              </div>

              <div className="panel-meta">Claims explained</div>
              <div className="claims">
                {result.claims.map((c) => (
                  <div key={c.key} className="claim">
                    <div className="claim-key">
                      {c.key} · {c.label}
                    </div>
                    <div className="claim-value">{formatValue(c.value)}</div>
                    {c.formatted ? (
                      <div className="claim-formatted">{c.formatted}</div>
                    ) : null}
                    <p className="claim-explain">{c.explanation}</p>
                  </div>
                ))}
              </div>
            </>
          ) : (
            !result.raw && (
              <p style={{ color: "var(--paper-faint)", margin: 0 }}>
                Nothing pasted yet. Decode happens only in this browser — JWT Glass
                never sends the token to a server and never verifies signatures.
                Load a DEMO example or paste a synthetic token.
              </p>
            )
          )}
        </section>
      </div>

      <footer className="footer">
        <p>
          JWT Glass is a portfolio demo by Saeed Rumaneh. Decode only — it does
          not verify signatures and must not be used as an auth library. See{" "}
          <code>SECURITY.md</code>.
        </p>
        <p>MIT © 2026 Saeed Rumaneh</p>
      </footer>
    </div>
  );
}
