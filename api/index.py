"""Vercel serverless entrypoint for ICSMOG.

This module exports an ASGI application (`app`) compatible with Vercel's Python runtime.
Modern web app with static file serving, API docs, and CORS support.
"""

from __future__ import annotations

import html
import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from src.services.cybersecurity import CybersecurityMonitoringService, seed_mvp_demo_data
from src.storage import CybersecurityEventStore


def _default_storage_path() -> str:
    configured = os.environ.get("ICSMOG_STORAGE_PATH")
    if configured:
        return configured

    # Vercel serverless file system is ephemeral; /tmp is writable per instance.
    if os.environ.get("VERCEL"):
        return "/tmp/cybersecurity.db"

    return "data/cybersecurity.db"


def _should_seed_demo_data() -> bool:
    raw = os.environ.get("ICSMOG_SEED_DEMO_DATA", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# Initialize service and optional demo data
_service = CybersecurityMonitoringService(
    store=CybersecurityEventStore(_default_storage_path())
)

if _should_seed_demo_data():
    seed_mvp_demo_data(_service)

# Create FastAPI app (ASGI-compatible for Vercel)
app = FastAPI(
    title="ICSMOG Cybersecurity API",
    version="1.0.0",
    description="Intelligent Computer Systems for Monitoring Organizations - Cybersecurity Module",
)

# Add CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (CSS, JS, etc.) if they exist
static_path = Path(__file__).parent.parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


def _escape_script_json(value: object) -> str:
        return json.dumps(value, separators=(",", ":")).replace("</", "<\\/")


def _render_alert_badge(threat_level: str) -> str:
        label = threat_level or "Unknown"
        level = label.strip().lower()
        if level in {"critical", "high"}:
                css_class = "critical"
        elif level in {"medium", "moderate"}:
                css_class = "warning"
        else:
                css_class = "ok"
        return f'<span class="status-badge {css_class}">{html.escape(label)}</span>'


def _render_dashboard_cards(data: dict[str, object]) -> str:
        alert_count = html.escape(str(data.get("alert_count") or 0))
        critical_count = html.escape(str(data.get("critical_count") or 0))
        network_event_count = html.escape(str(data.get("network_event_count") or 0))
        return f"""
        <div class="grid">
            <div class="card">
                <h3>Active Alerts</h3>
                <div class="card-value">{alert_count}</div>
                <div class="card-meta">Total active alerts</div>
            </div>
            <div class="card">
                <h3>Critical Issues</h3>
                <div class="card-value">{critical_count}</div>
                <div class="card-meta">Require immediate attention</div>
            </div>
            <div class="card">
                <h3>Network Events</h3>
                <div class="card-value">{network_event_count}</div>
                <div class="card-meta">Recent 24 hours</div>
            </div>
        </div>
        """


def _render_recent_alerts(data: dict[str, object]) -> str:
        recent_alerts = data.get("recent_alerts") or []
        rows: list[str] = []
        for alert in recent_alerts:
                if not isinstance(alert, dict):
                        continue
                timestamp = html.escape(str(alert.get("timestamp") or ""))
                threat_level = str(alert.get("threat_level") or "Unknown")
                source_ip = html.escape(str(alert.get("source_ip") or "N/A"))
                description = html.escape(str(alert.get("description") or "No description"))
                rows.append(
                        "<tr>"
                        f"<td>{timestamp}</td>"
                        f"<td>{_render_alert_badge(threat_level)}</td>"
                        f"<td>{source_ip}</td>"
                        f"<td>{description}</td>"
                        "</tr>"
                )

        if not rows:
                return ""

        return f"""
            <div class="panel" style="margin-top: 20px; padding: 20px;">
                <h2 style="margin: 0 0 16px 0;">Recent Alerts</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Threat Level</th>
                            <th>Source</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        """


def _get_index_html() -> str:
    """Generate index.html with external CSS/JS references."""
    initial_dashboard = _service.get_dashboard()
    dashboard_cards = _render_dashboard_cards(initial_dashboard)
    recent_alerts = _render_recent_alerts(initial_dashboard)
    dashboard_json = _escape_script_json(initial_dashboard)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ICSMOG Security Console</title>
  <link rel="stylesheet" href="/static/main.css">
</head>
<body>
  <div class="shell">
    <header>
      <h1>🛡️ ICSMOG Security Console</h1>
      <p style="margin: 8px 0 0 0; color: var(--ink-soft); font-size: 14px;">
        Intelligent Computer Systems for Monitoring Organizations
      </p>
      <div style="margin-top: 12px;">
        <a href="/docs" style="color: var(--accent); text-decoration: none; font-size: 14px; margin-right: 16px;">📚 API Docs</a>
        <a href="/health" style="color: var(--accent); text-decoration: none; font-size: 14px;">💚 Health Check</a>
      </div>
    </header>
        <div id="dashboard-content">
            {dashboard_cards}
            {recent_alerts}
        </div>
  </div>
    <script>
        window.__ICSMOG_INITIAL_DASHBOARD__ = {dashboard_json};
    </script>
    <script src="/static/app.js" defer></script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint - serves main dashboard."""
    return _get_index_html()


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Dashboard endpoint."""
    return _get_index_html()


@app.get("/dashboard/alerts/{alert_id}", response_class=HTMLResponse)
async def dashboard_alert(alert_id: str):
    """Alert detail endpoint."""
    from src.api.dashboard import render_alert_detail_html
    return render_alert_detail_html(alert_id)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return JSONResponse(
        {"status": "ok", "service": "icsmog-cybersecurity-api"},
        status_code=200
    )


@app.get("/cybersecurity/dashboard")
async def cybersecurity_dashboard():
    """Get cybersecurity dashboard data (JSON)."""
    return JSONResponse(_service.get_dashboard())


@app.get("/cybersecurity/alerts")
async def cybersecurity_alerts(
    threat_level: str = None,
    status: str = None,
    source_ip: str = None,
    destination_ip: str = None,
    protocol: str = None,
    port: int = None,
    query: str = None,
    limit: int = None,
):
    """Get cybersecurity alerts with optional filters."""
    try:
        alerts = _service.get_alerts(
            threat_level=threat_level,
            status=status,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            query=query,
            limit=limit,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    
    return JSONResponse(
        {
            "alerts": alerts,
            "triggered_rules": _service.get_triggered_rules(),
        }
    )


@app.get("/cybersecurity/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get a specific alert by ID."""
    alert = _service.get_alert_by_id(alert_id)
    if alert is None:
        return JSONResponse(
            {"error": "Alert not found", "alert_id": alert_id},
            status_code=404
        )
    return JSONResponse(alert)


@app.get("/cybersecurity/alerts/{alert_id}/investigation")
async def alert_investigation(alert_id: str, activity_limit: int = 10, related_limit: int = 5):
    """Get alert investigation details."""
    investigation = _service.get_alert_investigation(
        alert_id,
        activity_limit=activity_limit,
        related_limit=related_limit,
    )
    if investigation is None:
        return JSONResponse({"error": "alert not found"}, status_code=404)
    return JSONResponse(investigation)


@app.get("/cybersecurity/auth-events")
async def get_auth_events(
    username: str = None,
    source_ip: str = None,
    auth_method: str = None,
    result: str = None,
    target_resource: str = None,
    failure_reason: str = None,
    is_privileged: bool = None,
    query: str = None,
    limit: int = 20,
):
    """Get authentication events with optional filters."""
    try:
        auth_events = _service.get_auth_events(
            username=username,
            source_ip=source_ip,
            auth_method=auth_method,
            result=result,
            target_resource=target_resource,
            failure_reason=failure_reason,
            is_privileged=is_privileged,
            query=query,
            limit=limit,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    
    return JSONResponse({"auth_events": auth_events})


# Export as `app` for ASGI servers and Vercel
application = app
