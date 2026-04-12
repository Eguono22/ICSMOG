"""HTML dashboard pages for the ICSMOG cybersecurity API."""

from __future__ import annotations


def render_dashboard_html() -> str:
    """Return the single-page cybersecurity dashboard HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ICSMOG Security Console</title>
  <style>
    :root {
      --paper: #f6f1e7;
      --paper-strong: #fffaf2;
      --ink: #15232d;
      --ink-soft: #4b5f68;
      --accent: #c65a3d;
      --accent-deep: #8f321e;
      --signal: #2f7d60;
      --line: rgba(21, 35, 45, 0.14);
      --warning: #f0a33b;
      --critical: #b9362f;
      --shadow: 0 20px 45px rgba(73, 46, 28, 0.12);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Aptos", "Segoe UI Variable", "Trebuchet MS", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(198, 90, 61, 0.18), transparent 30%),
        radial-gradient(circle at top right, rgba(47, 125, 96, 0.12), transparent 28%),
        linear-gradient(180deg, #efe5d3 0%, var(--paper) 34%, #efe8dc 100%);
    }

    .shell {
      width: min(1180px, calc(100% - 32px));
      margin: 32px auto;
      padding: 24px;
      border: 1px solid rgba(255, 255, 255, 0.55);
      border-radius: 28px;
      background: rgba(255, 250, 242, 0.78);
      backdrop-filter: blur(18px);
      box-shadow: var(--shadow);
    }

    .hero {
      display: grid;
      grid-template-columns: 1.35fr 0.95fr;
      gap: 18px;
      margin-bottom: 20px;
    }

    .hero-panel,
    .panel,
    .metric {
      border: 1px solid var(--line);
      border-radius: 24px;
      background: rgba(255, 250, 242, 0.88);
    }

    .hero-panel {
      padding: 26px;
      position: relative;
      overflow: hidden;
    }

    .hero-panel::after {
      content: "";
      position: absolute;
      inset: auto -80px -80px auto;
      width: 220px;
      height: 220px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(198, 90, 61, 0.18), transparent 70%);
      pointer-events: none;
    }

    .eyebrow {
      display: inline-block;
      padding: 7px 12px;
      border-radius: 999px;
      background: rgba(198, 90, 61, 0.12);
      color: var(--accent-deep);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    h1,
    h2,
    h3 {
      font-family: "Bahnschrift", "Franklin Gothic Medium", sans-serif;
      letter-spacing: 0.01em;
      margin: 0;
    }

    h1 {
      margin-top: 14px;
      font-size: clamp(2rem, 5vw, 3.6rem);
      line-height: 0.95;
      max-width: 9ch;
    }

    .hero-copy {
      margin-top: 12px;
      max-width: 56ch;
      color: var(--ink-soft);
      font-size: 15px;
      line-height: 1.6;
    }

    .action-row,
    .metrics,
    .content-grid,
    .history-grid {
      display: grid;
      gap: 16px;
    }

    .action-row {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      margin-top: 20px;
    }

    button {
      border: 0;
      border-radius: 18px;
      padding: 14px 16px;
      text-align: left;
      font: inherit;
      cursor: pointer;
      transition: transform 160ms ease, box-shadow 160ms ease, opacity 160ms ease;
    }

    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 10px 22px rgba(21, 35, 45, 0.12);
    }

    button.primary {
      color: #fffaf2;
      background: linear-gradient(135deg, var(--accent), var(--accent-deep));
    }

    button.secondary {
      color: var(--ink);
      background: rgba(47, 125, 96, 0.13);
      border: 1px solid rgba(47, 125, 96, 0.18);
    }

    .button-title {
      display: block;
      font-weight: 700;
      margin-bottom: 4px;
    }

    .button-copy {
      font-size: 13px;
      opacity: 0.88;
    }

    .signal-panel {
      padding: 22px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      background:
        linear-gradient(180deg, rgba(21, 35, 45, 0.05), transparent),
        rgba(255, 250, 242, 0.88);
    }

    .signal-meter {
      margin-top: 18px;
      padding: 18px;
      border-radius: 20px;
      background: linear-gradient(135deg, rgba(21, 35, 45, 0.96), #23424d);
      color: #f8f4ed;
    }

    .signal-label {
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: rgba(248, 244, 237, 0.72);
    }

    .signal-value {
      margin-top: 10px;
      font-size: 2.7rem;
      line-height: 1;
      font-family: "Bahnschrift", "Franklin Gothic Medium", sans-serif;
    }

    .signal-subcopy {
      margin-top: 8px;
      font-size: 14px;
      color: rgba(248, 244, 237, 0.76);
    }

    .metrics {
      grid-template-columns: repeat(4, minmax(0, 1fr));
      margin-bottom: 16px;
    }

    .metric {
      padding: 18px;
      position: relative;
      overflow: hidden;
    }

    .metric::before {
      content: "";
      position: absolute;
      inset: auto 16px 0 auto;
      width: 72px;
      height: 72px;
      border-radius: 20px;
      background: rgba(198, 90, 61, 0.07);
      transform: rotate(18deg);
    }

    .metric-label {
      position: relative;
      z-index: 1;
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--ink-soft);
    }

    .metric-value {
      position: relative;
      z-index: 1;
      margin-top: 8px;
      font-size: 2rem;
      font-family: "Bahnschrift", "Franklin Gothic Medium", sans-serif;
    }

    .metric-note {
      position: relative;
      z-index: 1;
      margin-top: 6px;
      font-size: 13px;
      color: var(--ink-soft);
    }

    .content-grid {
      grid-template-columns: 1.1fr 0.9fr;
    }

    .history-grid {
      grid-template-columns: 0.95fr 1.05fr;
      margin-top: 16px;
    }

    .history-grid.single-panel {
      grid-template-columns: 1fr;
    }

    .panel {
      padding: 20px;
    }

    .panel-topline {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 16px;
    }

    .panel-copy {
      margin: 6px 0 0;
      font-size: 14px;
      line-height: 1.5;
      color: var(--ink-soft);
    }

    .filter-row {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }

    .filter-field {
      display: grid;
      gap: 6px;
    }

    .filter-field label {
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--ink-soft);
    }

    .filter-field input,
    .filter-field select {
      width: 100%;
      border: 1px solid rgba(21, 35, 45, 0.12);
      border-radius: 14px;
      padding: 11px 12px;
      font: inherit;
      color: var(--ink);
      background: rgba(255, 255, 255, 0.76);
    }

    .operator-controls {
      display: grid;
      gap: 14px;
    }

    .operator-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .operator-field {
      display: grid;
      gap: 6px;
    }

    .operator-field label {
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--ink-soft);
    }

    .operator-field input,
    .operator-field select,
    .operator-field textarea {
      width: 100%;
      border: 1px solid rgba(21, 35, 45, 0.12);
      border-radius: 14px;
      padding: 11px 12px;
      font: inherit;
      color: var(--ink);
      background: rgba(255, 255, 255, 0.76);
    }

    .operator-field textarea {
      min-height: 220px;
      resize: vertical;
      font-family: "Consolas", "Cascadia Code", monospace;
      line-height: 1.45;
    }

    .operator-actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    .operator-status {
      min-height: 22px;
      color: var(--ink-soft);
    }

    .operator-status.error {
      color: var(--critical);
    }

    .operator-status.success {
      color: var(--signal);
    }

    .status-pill {
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(47, 125, 96, 0.14);
      color: var(--signal);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }

    .stack {
      display: grid;
      gap: 12px;
    }

    .alert-card,
    .rule-card,
    .history-card {
      padding: 14px 15px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.54);
    }

    .alert-head,
    .rule-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
    }

    .alert-title,
    .rule-title {
      font-weight: 700;
      line-height: 1.4;
    }

    .muted {
      color: var(--ink-soft);
      font-size: 13px;
      line-height: 1.55;
    }

    .alert-link {
      color: inherit;
      text-decoration: none;
    }

    .alert-link:hover .alert-card {
      border-color: rgba(198, 90, 61, 0.35);
      box-shadow: 0 10px 22px rgba(21, 35, 45, 0.07);
    }

    .tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      white-space: nowrap;
    }

    .tag.high {
      color: #7b2c16;
      background: rgba(198, 90, 61, 0.16);
    }

    .tag.critical {
      color: #fff4f0;
      background: var(--critical);
    }

    .tag.medium {
      color: #7a5409;
      background: rgba(240, 163, 59, 0.2);
    }

    .tag.low,
    .tag.info,
    .tag.warning,
    .tag.open,
    .tag.acknowledged,
    .tag.resolved {
      color: var(--ink);
      background: rgba(21, 35, 45, 0.08);
    }

    .tag.success {
      color: #114b37;
      background: rgba(47, 125, 96, 0.16);
    }

    .tag.failed {
      color: #fff4f0;
      background: var(--critical);
    }

    .empty-state {
      padding: 20px;
      border: 1px dashed rgba(21, 35, 45, 0.18);
      border-radius: 20px;
      color: var(--ink-soft);
      background: rgba(255, 255, 255, 0.4);
    }

    .footer-note {
      margin-top: 16px;
      font-size: 13px;
      color: var(--ink-soft);
    }

    .pulse {
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--signal);
      box-shadow: 0 0 0 rgba(47, 125, 96, 0.45);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(47, 125, 96, 0.45); }
      70% { box-shadow: 0 0 0 16px rgba(47, 125, 96, 0); }
      100% { box-shadow: 0 0 0 0 rgba(47, 125, 96, 0); }
    }

    .fade-up {
      animation: fadeUp 420ms ease both;
    }

    @keyframes fadeUp {
      from {
        opacity: 0;
        transform: translateY(12px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @media (max-width: 920px) {
      .hero,
      .content-grid,
      .metrics {
        grid-template-columns: 1fr;
      }

      .history-grid,
      .operator-grid {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 640px) {
      .shell {
        width: min(100% - 18px, 100%);
        margin: 10px auto;
        padding: 14px;
        border-radius: 20px;
      }

      .hero-panel,
      .signal-panel,
      .panel,
      .metric {
        border-radius: 18px;
      }

      .action-row {
        grid-template-columns: 1fr;
      }

      .filter-row {
        grid-template-columns: 1fr;
      }

      h1 {
        max-width: none;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero fade-up">
      <article class="hero-panel">
        <span class="eyebrow">Cybersecurity Console</span>
        <h1>Signal First. Noise Last.</h1>
        <p class="hero-copy">
          ICSMOG turns persisted network and authentication events into explainable alerts.
          This dashboard rides directly on the API, so what you see here reflects the same
          service state your integrations would consume.
        </p>
        <div class="action-row">
          <button class="primary" id="demo-network">
            <span class="button-title">Inject Network Alert</span>
            <span class="button-copy">Send a high-risk SSH event and watch the alert stream update.</span>
          </button>
          <button class="secondary" id="demo-siem">
            <span class="button-title">Inject Auth Burst</span>
            <span class="button-copy">Create a brute-force pattern to trigger SIEM correlation.</span>
          </button>
        </div>
      </article>
      <aside class="hero-panel signal-panel fade-up">
        <div>
          <span class="eyebrow">Live State</span>
          <p class="hero-copy">A quick read on current persisted security pressure across detection and correlation layers.</p>
        </div>
        <div class="signal-meter">
          <div class="signal-label">Threat Posture</div>
          <div class="signal-value" id="signal-value">Calm</div>
          <div class="signal-subcopy" id="signal-copy">No alerts loaded yet.</div>
        </div>
      </aside>
    </section>

    <section class="metrics fade-up">
      <article class="metric">
        <div class="metric-label">Network Events</div>
        <div class="metric-value" id="metric-network-events">0</div>
        <div class="metric-note">Persisted traffic analyzed by IDS/IPS.</div>
      </article>
      <article class="metric">
        <div class="metric-label">Open Alerts</div>
        <div class="metric-value" id="metric-open-alerts">0</div>
        <div class="metric-note">Active IDS/IPS alerts waiting for review.</div>
      </article>
      <article class="metric">
        <div class="metric-label">SIEM Events</div>
        <div class="metric-value" id="metric-siem-events">0</div>
        <div class="metric-note">Security events retained for correlation.</div>
      </article>
      <article class="metric">
        <div class="metric-label">Triggered Rules</div>
        <div class="metric-value" id="metric-rules">0</div>
        <div class="metric-note">Correlation rules currently recorded.</div>
      </article>
    </section>

    <section class="content-grid fade-up">
      <article class="panel">
        <div class="panel-topline">
          <div>
            <h2>Recent Alerts</h2>
            <p class="panel-copy">Explainable detections from the persisted intrusion pipeline.</p>
          </div>
          <div class="status-pill"><span class="pulse"></span>&nbsp;<span id="status-text">Syncing</span></div>
        </div>
        <div class="filter-row">
          <div class="filter-field">
            <label for="filter-threat-level">Threat Level</label>
            <select id="filter-threat-level">
              <option value="">All levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div class="filter-field">
            <label for="filter-status">Alert Status</label>
            <select id="filter-status">
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
          <div class="filter-field">
            <label for="filter-source-ip">Source IP</label>
            <input id="filter-source-ip" type="text" placeholder="198.51.100.20">
          </div>
        </div>
        <div class="stack" id="alerts-list">
          <div class="empty-state">No alerts yet. Use the demo actions above or post to the API.</div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-topline">
          <div>
            <h2>Rule Activity</h2>
            <p class="panel-copy">Correlation output from the SIEM workflow plus current severity mix.</p>
          </div>
        </div>
        <div class="stack" id="rules-list">
          <div class="empty-state">No correlation rules have fired yet.</div>
        </div>
        <div class="footer-note" id="severity-summary">Severity profile will appear after events are ingested.</div>
      </article>
    </section>

    <section class="history-grid fade-up">
      <article class="panel">
        <div class="panel-topline">
          <div>
            <h2>Operator Controls</h2>
            <p class="panel-copy">Paste inline CSV, choose the target pipeline, and trigger imports without leaving the console.</p>
          </div>
        </div>
        <div class="operator-controls">
          <div class="operator-grid">
            <div class="operator-field">
              <label for="operator-name">Operator Name</label>
              <input id="operator-name" type="text" placeholder="SOC analyst">
            </div>
            <div class="operator-field">
              <label for="operator-key">Operator Key</label>
              <input id="operator-key" type="password" placeholder="icsmog-demo-key">
            </div>
          </div>
          <div class="operator-grid">
            <div class="operator-field">
              <label for="import-target">Import Target</label>
              <select id="import-target">
                <option value="network">Network</option>
                <option value="security">Security</option>
              </select>
            </div>
            <div class="operator-field">
              <label for="import-template">Template</label>
              <select id="import-template">
                <option value="blank">Blank</option>
                <option value="network-sample">Network Sample</option>
                <option value="security-sample">Security Sample</option>
              </select>
            </div>
          </div>
          <div class="operator-field">
            <label for="import-editor">CSV Payload</label>
            <textarea
              id="import-editor"
              spellcheck="false"
              placeholder="Paste CSV rows here or load a sample template."
            ></textarea>
          </div>
          <div class="operator-actions">
            <button class="primary" id="run-import" type="button">
              <span class="button-title">Run CSV Import</span>
              <span class="button-copy">Send the current CSV payload through the selected pipeline.</span>
            </button>
            <button class="secondary" id="clear-import" type="button">
              <span class="button-title">Clear Editor</span>
              <span class="button-copy">Reset the editor so you can paste a fresh payload.</span>
            </button>
          </div>
          <div class="operator-status" id="operator-status">Set operator credentials, then run an inline CSV import.</div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-topline">
          <div>
            <h2>Import History</h2>
            <p class="panel-copy">Recent watch-folder and CSV import activity recorded in persistent storage.</p>
          </div>
        </div>
        <div class="stack" id="import-history-list">
          <div class="empty-state">No CSV imports have been recorded yet.</div>
        </div>
      </article>
    </section>

    <section class="history-grid single-panel fade-up">
      <article class="panel">
        <div class="panel-topline">
          <div>
            <h2>Audit Trail</h2>
            <p class="panel-copy">Protected operator actions are recorded here so import and alert decisions stay attributable.</p>
          </div>
        </div>
        <div class="stack" id="audit-log-list">
          <div class="empty-state">No operator actions have been recorded yet.</div>
        </div>
      </article>
    </section>
  </main>

  <script>
    const dashboardState = {
      dashboard: null,
      alerts: [],
      triggeredRules: [],
      imports: [],
      auditLog: [],
      filters: {
        threatLevel: "",
        status: "",
        sourceIp: "",
      },
    };

    const csvTemplates = {
      blank: "",
      "network-sample":
        "source_ip,destination_ip,port,protocol,payload_size\\n" +
        "198.51.100.70,10.0.0.70,22,SSH,180\\n" +
        "198.51.100.71,10.0.0.71,443,TLS,1200\\n",
      "security-sample":
        "source,category,severity,message\\n" +
        "auth-service,authentication,error,Login failed\\n" +
        "auth-service,authentication,error,Login failed\\n" +
        "auth-service,authentication,error,Login failed\\n" +
        "auth-service,authentication,error,Login failed\\n" +
        "auth-service,authentication,error,Login failed\\n",
    };

    async function fetchJson(path, options = {}) {
      const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      };
      const response = await fetch(path, {
        ...options,
        headers,
      });

      if (!response.ok) {
        const errorPayload = await response.json().catch(() => ({ error: "Request failed" }));
        throw new Error(errorPayload.error || `Request failed with status ${response.status}`);
      }

      return response.json();
    }

    async function refreshDashboard() {
      try {
        const [dashboard, alertPayload, importPayload, auditPayload] = await Promise.all([
          fetchJson("/cybersecurity/dashboard"),
          fetchJson(buildAlertEndpoint()),
          fetchJson("/cybersecurity/import-history?limit=8"),
          fetchJson("/cybersecurity/audit-log?limit=8"),
        ]);

        dashboardState.dashboard = dashboard;
        dashboardState.alerts = alertPayload.alerts || [];
        dashboardState.triggeredRules = alertPayload.triggered_rules || [];
        dashboardState.imports = importPayload.imports || [];
        dashboardState.auditLog = auditPayload.audit_log || [];
        render();
        setStatus("Live");
      } catch (error) {
        setStatus("API Error");
        document.getElementById("status-text").textContent = "API Error";
        document.getElementById("alerts-list").innerHTML =
          `<div class="empty-state">${escapeHtml(error.message)}</div>`;
      }
    }

    function render() {
      renderMetrics();
      renderSignal();
      renderAlerts();
      renderRules();
      renderImportHistory();
      renderAuditLog();
    }

    function renderMetrics() {
      const ips = dashboardState.dashboard?.ips || {};
      const siem = dashboardState.dashboard?.siem || {};
      document.getElementById("metric-network-events").textContent = ips.total_events ?? 0;
      document.getElementById("metric-open-alerts").textContent = ips.open_alerts ?? 0;
      document.getElementById("metric-siem-events").textContent = siem.total_events ?? 0;
      document.getElementById("metric-rules").textContent = siem.triggered_rules ?? 0;
    }

    function renderSignal() {
      const ips = dashboardState.dashboard?.ips || {};
      const criticalCount = ips.threat_counts?.critical || 0;
      const highCount = ips.threat_counts?.high || 0;
      const openAlerts = ips.open_alerts || 0;

      let posture = "Calm";
      let copy = "No active threats are currently persisted.";

      if (criticalCount > 0) {
        posture = "Critical";
        copy = `${criticalCount} critical alert${criticalCount === 1 ? "" : "s"} detected. Immediate review recommended.`;
      } else if (highCount > 0) {
        posture = "Elevated";
        copy = `${highCount} high-severity alert${highCount === 1 ? "" : "s"} present across ${openAlerts} open case${openAlerts === 1 ? "" : "s"}.`;
      } else if (openAlerts > 0) {
        posture = "Observed";
        copy = `${openAlerts} open alert${openAlerts === 1 ? "" : "s"} waiting for follow-up.`;
      }

      document.getElementById("signal-value").textContent = posture;
      document.getElementById("signal-copy").textContent = copy;
    }

    function renderAlerts() {
      const container = document.getElementById("alerts-list");
      if (!dashboardState.alerts.length) {
        container.innerHTML = '<div class="empty-state">No alerts matched the current filters. Clear a filter or inject a new event.</div>';
        return;
      }

      const cards = dashboardState.alerts
        .map((alert) => `
          <a class="alert-link" href="/dashboard/alerts/${encodeURIComponent(alert.alert_id)}">
            <article class="alert-card">
              <div class="alert-head">
                <div class="alert-title">${escapeHtml(alert.description)}</div>
                <span class="tag ${escapeHtml(alert.threat_level)}">${escapeHtml(alert.threat_level)}</span>
              </div>
              <div class="muted">
                ${escapeHtml(alert.source_ip)} -> ${escapeHtml(alert.destination_ip)} on port ${escapeHtml(String(alert.port))}
              </div>
              <div class="muted">
                Protocol ${escapeHtml(alert.protocol)} | Payload ${escapeHtml(String(alert.payload_size))} bytes | Status ${escapeHtml(alert.status)}
              </div>
              <div class="muted">
                Alert ${escapeHtml(alert.alert_id)} | Created ${formatTimestamp(alert.created_at)}
              </div>
            </article>
          </a>
        `)
        .join("");

      container.innerHTML = cards;
    }

    function renderRules() {
      const container = document.getElementById("rules-list");
      const severity = dashboardState.dashboard?.siem?.severity_breakdown || {};

      if (!dashboardState.triggeredRules.length) {
        container.innerHTML = '<div class="empty-state">No correlation rules have fired yet.</div>';
      } else {
        container.innerHTML = dashboardState.triggeredRules
          .slice(-6)
          .reverse()
          .map((rule) => `
            <article class="rule-card">
              <div class="rule-head">
                <div class="rule-title">${escapeHtml(rule.rule)}</div>
                <span class="tag ${escapeHtml(rule.severity)}">${escapeHtml(rule.severity)}</span>
              </div>
              <div class="muted">${escapeHtml(rule.description)}</div>
              <div class="muted">Triggered ${formatTimestamp(rule.triggered_at)}</div>
            </article>
          `)
          .join("");
      }

      document.getElementById("severity-summary").textContent =
        `Severity mix: info ${severity.info || 0}, warning ${severity.warning || 0}, error ${severity.error || 0}, critical ${severity.critical || 0}.`;
    }

    function renderImportHistory() {
      const container = document.getElementById("import-history-list");
      if (!dashboardState.imports.length) {
        container.innerHTML = '<div class="empty-state">No CSV imports have been recorded yet.</div>';
        return;
      }

      container.innerHTML = dashboardState.imports
        .map((entry) => `
          <article class="history-card">
            <div class="alert-head">
              <div class="alert-title">${escapeHtml(entry.file_path)}</div>
              <span class="tag ${escapeHtml(entry.status)}">${escapeHtml(entry.status)}</span>
            </div>
            <div class="muted">Operator ${escapeHtml(entry.operator_name || "system")}</div>
            <div class="muted">${escapeHtml(entry.import_type.replaceAll("_", " "))} at ${formatTimestamp(entry.imported_at)}</div>
            ${entry.error_message ? `<div class="muted">Error: ${escapeHtml(entry.error_message)}</div>` : ""}
          </article>
        `)
        .join("");
    }

    function renderAuditLog() {
      const container = document.getElementById("audit-log-list");
      if (!dashboardState.auditLog.length) {
        container.innerHTML = '<div class="empty-state">No operator actions have been recorded yet.</div>';
        return;
      }

      container.innerHTML = dashboardState.auditLog
        .map((entry) => `
          <article class="history-card">
            <div class="alert-head">
              <div class="alert-title">${escapeHtml(entry.action_type.replaceAll("_", " "))}</div>
              <span class="tag ${escapeHtml(entry.status)}">${escapeHtml(entry.status)}</span>
            </div>
            <div class="muted">Operator ${escapeHtml(entry.operator_name)} targeted ${escapeHtml(entry.target)}</div>
            <div class="muted">${formatTimestamp(entry.created_at)}</div>
          </article>
        `)
        .join("");
    }

    function setStatus(label) {
      document.getElementById("status-text").textContent = label;
    }

    function setOperatorStatus(message, tone = "") {
      const node = document.getElementById("operator-status");
      node.textContent = message;
      node.className = tone ? `operator-status ${tone}` : "operator-status";
    }

    function loadOperatorCredentials() {
      document.getElementById("operator-name").value = localStorage.getItem("icsmog.operatorName") || "";
      document.getElementById("operator-key").value = localStorage.getItem("icsmog.operatorKey") || "icsmog-demo-key";
    }

    function persistOperatorCredentials() {
      localStorage.setItem("icsmog.operatorName", document.getElementById("operator-name").value.trim());
      localStorage.setItem("icsmog.operatorKey", document.getElementById("operator-key").value);
    }

    function getOperatorHeaders() {
      const operatorName = document.getElementById("operator-name").value.trim();
      const operatorKey = document.getElementById("operator-key").value;
      if (!operatorName) {
        throw new Error("Operator name is required for protected actions.");
      }
      if (!operatorKey) {
        throw new Error("Operator key is required for protected actions.");
      }
      persistOperatorCredentials();
      return {
        "X-Operator-Name": operatorName,
        "X-Operator-Key": operatorKey,
      };
    }

    function buildAlertEndpoint() {
      const params = new URLSearchParams();
      if (dashboardState.filters.threatLevel) {
        params.set("threat_level", dashboardState.filters.threatLevel);
      }
      if (dashboardState.filters.status) {
        params.set("status", dashboardState.filters.status);
      }
      if (dashboardState.filters.sourceIp) {
        params.set("source_ip", dashboardState.filters.sourceIp);
      }
      params.set("limit", "12");
      const query = params.toString();
      return query ? `/cybersecurity/alerts?${query}` : "/cybersecurity/alerts";
    }

    async function injectNetworkDemo() {
      setStatus("Injecting");
      await fetchJson("/cybersecurity/network-events", {
        method: "POST",
        body: JSON.stringify({
          events: [
            {
              source_ip: "198.51.100.120",
              destination_ip: "10.0.0.10",
              port: 22,
              protocol: "SSH",
              payload_size: 384,
            },
          ],
        }),
      });
      await refreshDashboard();
    }

    async function injectSiemDemo() {
      setStatus("Injecting");
      await fetchJson("/cybersecurity/security-events", {
        method: "POST",
        body: JSON.stringify({
          events: Array.from({ length: 5 }, () => ({
            source: "auth-service",
            category: "authentication",
            severity: "error",
            message: "Login failed",
          })),
        }),
      });
      await refreshDashboard();
    }

    function applyImportTemplate() {
      const template = document.getElementById("import-template").value;
      document.getElementById("import-editor").value = csvTemplates[template] || "";

      if (template === "network-sample") {
        document.getElementById("import-target").value = "network";
      } else if (template === "security-sample") {
        document.getElementById("import-target").value = "security";
      }

      setOperatorStatus(
        template === "blank"
          ? "Editor cleared. Paste a CSV payload or load a sample template."
          : "Sample template loaded. Review the payload and run the import when ready."
      );
    }

    async function runInlineImport() {
      const target = document.getElementById("import-target").value;
      const csvText = document.getElementById("import-editor").value.trim();

      if (!csvText) {
        setOperatorStatus("Add CSV rows before running an import.", "error");
        return;
      }

      setOperatorStatus(`Importing ${target} CSV payload...`);
      const result = await fetchJson(`/cybersecurity/import/${target}-csv`, {
        method: "POST",
        headers: getOperatorHeaders(),
        body: JSON.stringify({ csv_text: csvText }),
      });
      setOperatorStatus(
        `Imported ${result.ingested_events} ${target} event${result.ingested_events === 1 ? "" : "s"} from inline CSV as ${result.operator_name}.`,
        "success"
      );
      await refreshDashboard();
    }

    function formatTimestamp(value) {
      if (!value) {
        return "unknown time";
      }
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {
        return value;
      }
      return date.toLocaleString();
    }

    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    document.getElementById("demo-network").addEventListener("click", () => {
      injectNetworkDemo().catch((error) => {
        setStatus("API Error");
        alert(error.message);
      });
    });

    document.getElementById("demo-siem").addEventListener("click", () => {
      injectSiemDemo().catch((error) => {
        setStatus("API Error");
        alert(error.message);
      });
    });

    document.getElementById("filter-threat-level").addEventListener("change", (event) => {
      dashboardState.filters.threatLevel = event.target.value;
      refreshDashboard();
    });

    document.getElementById("filter-status").addEventListener("change", (event) => {
      dashboardState.filters.status = event.target.value;
      refreshDashboard();
    });

    document.getElementById("filter-source-ip").addEventListener("input", (event) => {
      dashboardState.filters.sourceIp = event.target.value.trim();
      refreshDashboard();
    });

    document.getElementById("import-template").addEventListener("change", () => {
      applyImportTemplate();
    });

    document.getElementById("clear-import").addEventListener("click", () => {
      document.getElementById("import-template").value = "blank";
      applyImportTemplate();
    });

    document.getElementById("run-import").addEventListener("click", () => {
      runInlineImport().catch((error) => {
        setOperatorStatus(error.message, "error");
      });
    });

    document.getElementById("operator-name").addEventListener("input", () => {
      persistOperatorCredentials();
    });

    document.getElementById("operator-key").addEventListener("input", () => {
      persistOperatorCredentials();
    });

    loadOperatorCredentials();
    applyImportTemplate();
    refreshDashboard();
    setInterval(refreshDashboard, 8000);
  </script>
</body>
</html>
"""


def render_alert_detail_html(alert_id: str) -> str:
    """Return the alert investigation detail page HTML."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ICSMOG Alert {alert_id}</title>
  <style>
    :root {{
      --paper: #f5efe1;
      --panel: rgba(255, 250, 242, 0.9);
      --ink: #17242d;
      --muted: #546872;
      --accent: #c65a3d;
      --accent-deep: #8b301c;
      --line: rgba(23, 36, 45, 0.12);
      --shadow: 0 20px 45px rgba(73, 46, 28, 0.12);
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Aptos", "Segoe UI Variable", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top right, rgba(198, 90, 61, 0.15), transparent 28%),
        linear-gradient(180deg, #ede3d2 0%, var(--paper) 40%, #efe7d8 100%);
    }}

    .wrap {{
      width: min(980px, calc(100% - 28px));
      margin: 28px auto;
      display: grid;
      gap: 16px;
    }}

    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 22px;
      box-shadow: var(--shadow);
    }}

    .eyebrow {{
      display: inline-block;
      padding: 7px 12px;
      border-radius: 999px;
      background: rgba(198, 90, 61, 0.12);
      color: var(--accent-deep);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    h1, h2 {{
      font-family: "Bahnschrift", "Franklin Gothic Medium", sans-serif;
      margin: 0;
    }}

    h1 {{
      margin-top: 14px;
      font-size: clamp(2rem, 5vw, 3.2rem);
      line-height: 1;
      max-width: 12ch;
    }}

    p {{
      color: var(--muted);
      line-height: 1.6;
    }}

    .back-link {{
      color: var(--accent-deep);
      text-decoration: none;
      font-weight: 700;
    }}

    .action-bar {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 18px;
    }}

    .credential-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}

    .field {{
      display: grid;
      gap: 6px;
    }}

    .field label {{
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }}

    .field input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 11px 12px;
      font: inherit;
      color: var(--ink);
      background: rgba(255, 255, 255, 0.82);
    }}

    .action-button {{
      border: 0;
      border-radius: 16px;
      padding: 12px 16px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      color: #fffaf2;
      background: linear-gradient(135deg, var(--accent), var(--accent-deep));
    }}

    .action-button.secondary {{
      color: var(--ink);
      background: rgba(23, 36, 45, 0.08);
    }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }}

    .datum {{
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.56);
    }}

    .label {{
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }}

    .value {{
      margin-top: 8px;
      font-size: 1.1rem;
      font-weight: 700;
      word-break: break-word;
    }}

    pre {{
      margin: 0;
      padding: 16px;
      border-radius: 18px;
      background: #1b2c35;
      color: #edf2f0;
      overflow: auto;
      font-size: 13px;
      line-height: 1.55;
    }}

    .empty {{
      padding: 20px;
      border: 1px dashed var(--line);
      border-radius: 18px;
      color: var(--muted);
    }}

    .status-note {{
      margin-top: 10px;
      color: var(--muted);
      font-size: 14px;
    }}

    @media (max-width: 700px) {{
      .credential-grid {{
        grid-template-columns: 1fr;
      }}

      .grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="panel">
      <a class="back-link" href="/dashboard">Back to Dashboard</a>
      <div class="eyebrow">Alert Investigation</div>
      <h1 id="alert-title">Loading alert {alert_id}</h1>
      <p id="alert-copy">Fetching the persisted alert record and its investigation details.</p>
      <div class="credential-grid">
        <div class="field">
          <label for="operator-name">Operator Name</label>
          <input id="operator-name" type="text" placeholder="SOC analyst">
        </div>
        <div class="field">
          <label for="operator-key">Operator Key</label>
          <input id="operator-key" type="password" placeholder="icsmog-demo-key">
        </div>
      </div>
      <div class="action-bar">
        <button class="action-button secondary" id="acknowledge-button" type="button">Acknowledge</button>
        <button class="action-button" id="resolve-button" type="button">Resolve</button>
      </div>
      <div class="status-note" id="action-status">No action taken yet.</div>
    </section>
    <section class="panel">
      <h2>Evidence</h2>
      <div class="grid" id="detail-grid">
        <div class="empty">Loading alert details...</div>
      </div>
    </section>
    <section class="panel">
      <h2>Raw Record</h2>
      <pre id="raw-json">Loading...</pre>
    </section>
  </main>
  <script>
    const alertId = {alert_id!r};

    function loadOperatorCredentials() {{
      document.getElementById("operator-name").value = localStorage.getItem("icsmog.operatorName") || "";
      document.getElementById("operator-key").value = localStorage.getItem("icsmog.operatorKey") || "icsmog-demo-key";
    }}

    function persistOperatorCredentials() {{
      localStorage.setItem("icsmog.operatorName", document.getElementById("operator-name").value.trim());
      localStorage.setItem("icsmog.operatorKey", document.getElementById("operator-key").value);
    }}

    function getOperatorHeaders() {{
      const operatorName = document.getElementById("operator-name").value.trim();
      const operatorKey = document.getElementById("operator-key").value;
      if (!operatorName) {{
        throw new Error("Operator name is required for alert actions.");
      }}
      if (!operatorKey) {{
        throw new Error("Operator key is required for alert actions.");
      }}
      persistOperatorCredentials();
      return {{
        "X-Operator-Name": operatorName,
        "X-Operator-Key": operatorKey,
      }};
    }}

    async function loadAlert() {{
      const response = await fetch(`/cybersecurity/alerts/${{encodeURIComponent(alertId)}}`);
      if (response.status === 404) {{
        document.getElementById("alert-title").textContent = "Alert not found";
        document.getElementById("alert-copy").textContent = "The requested alert is not present in the persisted history.";
        document.getElementById("detail-grid").innerHTML = '<div class="empty">Try returning to the dashboard and selecting a different alert.</div>';
        document.getElementById("raw-json").textContent = '{{"error": "Alert not found"}}';
        return;
      }}
      const payload = await response.json();
      render(payload);
    }}

    function render(alert) {{
      document.getElementById("alert-title").textContent = alert.description;
      document.getElementById("alert-copy").textContent =
        `Alert ${{alert.alert_id}} was raised for ${{alert.source_ip}} targeting ${{alert.destination_ip}} on port ${{alert.port}}.`;
      document.getElementById("action-status").textContent =
        `Current status: ${{alert.status}}.`;
      document.getElementById("acknowledge-button").disabled = alert.status === "resolved";
      document.getElementById("resolve-button").disabled = alert.status === "resolved";
      document.getElementById("detail-grid").innerHTML = [
        ['Alert ID', alert.alert_id],
        ['Threat Level', alert.threat_level],
        ['Status', alert.status],
        ['Source IP', alert.source_ip],
        ['Destination IP', alert.destination_ip],
        ['Protocol', alert.protocol],
        ['Port', String(alert.port)],
        ['Payload Size', `${{alert.payload_size}} bytes`],
        ['Created At', formatTimestamp(alert.created_at)],
        ['Resolved At', alert.resolved_at ? formatTimestamp(alert.resolved_at) : 'Not resolved'],
      ].map(([label, value]) => `
        <article class="datum">
          <div class="label">${{escapeHtml(label)}}</div>
          <div class="value">${{escapeHtml(value)}}</div>
        </article>
      `).join('');
      document.getElementById("raw-json").textContent = JSON.stringify(alert, null, 2);
    }}

    async function applyAction(action) {{
      const operatorHeaders = getOperatorHeaders();
      const response = await fetch(`/cybersecurity/alerts/${{encodeURIComponent(alertId)}}/${{action}}`, {{
        method: "POST",
        headers: operatorHeaders,
      }});
      const payload = await response.json();
      if (!response.ok) {{
        throw new Error(payload.error || `Unable to ${{action}} alert`);
      }}
      render(payload);
      document.getElementById("action-status").textContent =
        `Alert updated by ${{payload.updated_by}}: status is now ${{payload.status}}.`;
    }}

    function formatTimestamp(value) {{
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {{
        return value;
      }}
      return date.toLocaleString();
    }}

    function escapeHtml(value) {{
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }}

    loadAlert().catch((error) => {{
      document.getElementById("alert-title").textContent = "Alert load failed";
      document.getElementById("alert-copy").textContent = error.message;
      document.getElementById("detail-grid").innerHTML = '<div class="empty">The alert details could not be loaded from the API.</div>';
      document.getElementById("raw-json").textContent = JSON.stringify({{ error: error.message }}, null, 2);
    }});

    document.getElementById("operator-name").addEventListener("input", () => {{
      persistOperatorCredentials();
    }});

    document.getElementById("operator-key").addEventListener("input", () => {{
      persistOperatorCredentials();
    }});

    document.getElementById("acknowledge-button").addEventListener("click", () => {{
      applyAction("acknowledge").catch((error) => {{
        document.getElementById("action-status").textContent = error.message;
      }});
    }});

    document.getElementById("resolve-button").addEventListener("click", () => {{
      applyAction("resolve").catch((error) => {{
        document.getElementById("action-status").textContent = error.message;
      }});
    }});

    loadOperatorCredentials();
  </script>
</body>
</html>
"""
