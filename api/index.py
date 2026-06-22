"""Vercel serverless entrypoint for ICSMOG.

This module exports an ASGI application (`app`) compatible with Vercel's Python runtime.
Vercel's Python runtime requires FastAPI/Starlette ASGI apps, not raw HTTP handlers.
"""

from __future__ import annotations

import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

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
app = FastAPI(title="ICSMOG Cybersecurity API")


@app.get("/")
async def root():
    """Root endpoint - serves dashboard."""
    from src.api.dashboard import render_dashboard_html
    return HTMLResponse(render_dashboard_html())


@app.get("/dashboard")
async def dashboard():
    """Dashboard endpoint."""
    from src.api.dashboard import render_dashboard_html
    return HTMLResponse(render_dashboard_html())


@app.get("/dashboard/alerts/{alert_id}")
async def dashboard_alert(alert_id: str):
    """Alert detail endpoint."""
    from src.api.dashboard import render_alert_detail_html
    return HTMLResponse(render_alert_detail_html(alert_id))


@app.get("/health")
async def health():
    """Health check endpoint."""
    return JSONResponse(
        {"status": "ok", "service": "icsmog-cybersecurity-api"},
        status_code=200
    )


@app.get("/cybersecurity/dashboard")
async def cybersecurity_dashboard():
    """Get cybersecurity dashboard data."""
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
