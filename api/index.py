"""Vercel serverless entrypoint for ICSMOG.

This module exports an ASGI application (`app`) compatible with Vercel's Python runtime.
Modern web app with static file serving, API docs, and CORS support.
"""

from __future__ import annotations

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


def _get_index_html() -> str:
    """Generate index.html with external CSS/JS references."""
    return """<!DOCTYPE html>
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
    <div id="dashboard-content" class="loading">Loading dashboard...</div>
  </div>
  <script src="/static/app.js"></script>
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
