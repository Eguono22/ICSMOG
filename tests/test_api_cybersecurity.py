"""Tests for the minimal cybersecurity HTTP API."""

from __future__ import annotations

import json
import threading
import tempfile
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from src.api.cybersecurity import build_handler
from src.services.cybersecurity import CybersecurityMonitoringService
from src.storage import CybersecurityEventStore


def _start_test_server(
    service: CybersecurityMonitoringService | None = None,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    if service is None:
        service = CybersecurityMonitoringService()
    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _read_json(url: str, method: str = "GET", payload: dict | None = None) -> dict:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def test_health_endpoint_returns_ok():
    server, thread = _start_test_server()
    try:
        payload = _read_json(
            f"http://127.0.0.1:{server.server_address[1]}/health"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert payload["status"] == "ok"


def test_dashboard_page_renders_html():
    server, thread = _start_test_server()
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{server.server_address[1]}/dashboard"
        ) as response:
            html = response.read().decode("utf-8")
            content_type = response.headers.get("Content-Type")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert "ICSMOG Security Console" in html
    assert "text/html" in content_type


def test_network_event_endpoint_updates_dashboard_and_alerts():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = _read_json(
            f"{base_url}/cybersecurity/network-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source_ip": "198.51.100.20",
                        "destination_ip": "10.0.0.10",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 300,
                    }
                ]
            },
        )
        alerts = _read_json(f"{base_url}/cybersecurity/alerts")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["latest_alert"] == "Access attempt on high-risk port 22"
    assert alerts["alerts"][0]["source_ip"] == "198.51.100.20"
    assert "alert_id" in alerts["alerts"][0]


def test_security_event_endpoint_triggers_rule():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = _read_json(
            f"{base_url}/cybersecurity/security-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source": "auth-service",
                        "category": "authentication",
                        "severity": "error",
                        "message": "Login failed",
                    }
                    for _ in range(5)
                ]
            },
        )
        dashboard = _read_json(f"{base_url}/cybersecurity/dashboard")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["triggered_rules"][0]["rule"] == "brute_force_detection"
    assert dashboard["siem"]["triggered_rules"] == 1


def test_api_service_reloads_persisted_history():
    with tempfile.TemporaryDirectory() as temp_dir:
        store = CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
        seeded_service = CybersecurityMonitoringService(store=store)
        seeded_service.ingest_network_payload(
            {
                "events": [
                    {
                        "source_ip": "198.51.100.77",
                        "destination_ip": "10.0.0.15",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 200,
                    }
                ]
            }
        )

        reloaded_service = CybersecurityMonitoringService(store=store)
        server, thread = _start_test_server(reloaded_service)
        try:
            dashboard = _read_json(
                f"http://127.0.0.1:{server.server_address[1]}/cybersecurity/dashboard"
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert dashboard["ips"]["total_events"] == 1
    assert dashboard["ips"]["total_alerts"] == 1


def test_alerts_endpoint_supports_filtering_and_detail_lookup():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _read_json(
            f"{base_url}/cybersecurity/network-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source_ip": "198.51.100.31",
                        "destination_ip": "10.0.0.10",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 100,
                    },
                    {
                        "source_ip": "198.51.100.32",
                        "destination_ip": "10.0.0.11",
                        "port": 80,
                        "protocol": "HTTP",
                        "payload_size": 20000,
                    },
                ]
            },
        )
        filtered = _read_json(
            f"{base_url}/cybersecurity/alerts?threat_level=high&source_ip=198.51.100.31"
        )
        alert_id = filtered["alerts"][0]["alert_id"]
        detail = _read_json(f"{base_url}/cybersecurity/alerts/{alert_id}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert len(filtered["alerts"]) == 1
    assert filtered["alerts"][0]["threat_level"] == "high"
    assert detail["source_ip"] == "198.51.100.31"


def test_alert_detail_page_renders_html():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _read_json(
            f"{base_url}/cybersecurity/network-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source_ip": "198.51.100.40",
                        "destination_ip": "10.0.0.50",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 120,
                    }
                ]
            },
        )
        alerts = _read_json(f"{base_url}/cybersecurity/alerts")
        alert_id = alerts["alerts"][0]["alert_id"]
        with urllib.request.urlopen(
            f"{base_url}/dashboard/alerts/{alert_id}"
        ) as response:
            html = response.read().decode("utf-8")
            content_type = response.headers.get("Content-Type")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert alert_id in html
    assert "Alert Investigation" in html
    assert "text/html" in content_type


def test_alert_lifecycle_endpoints_update_status():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _read_json(
            f"{base_url}/cybersecurity/network-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source_ip": "198.51.100.41",
                        "destination_ip": "10.0.0.51",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 121,
                    }
                ]
            },
        )
        alerts = _read_json(f"{base_url}/cybersecurity/alerts")
        alert_id = alerts["alerts"][0]["alert_id"]
        acknowledged = _read_json(
            f"{base_url}/cybersecurity/alerts/{alert_id}/acknowledge",
            method="POST",
            payload={},
        )
        resolved = _read_json(
            f"{base_url}/cybersecurity/alerts/{alert_id}/resolve",
            method="POST",
            payload={},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert acknowledged["status"] == "acknowledged"
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"] is not None


def test_network_csv_import_endpoint_accepts_inline_csv():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = _read_json(
            f"{base_url}/cybersecurity/import/network-csv",
            method="POST",
            payload={
                "csv_text": (
                    "source_ip,destination_ip,port,protocol,payload_size\n"
                    "198.51.100.61,10.0.0.61,22,SSH,150\n"
                    "198.51.100.62,10.0.0.62,80,HTTP,15000\n"
                )
            },
        )
        alerts = _read_json(f"{base_url}/cybersecurity/alerts")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["ingested_events"] == 2
    assert result["imported_from"] == "inline_csv_text"
    assert len(alerts["alerts"]) == 2


def test_security_csv_import_endpoint_accepts_file_path():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = _read_json(
            f"{base_url}/cybersecurity/import/security-csv",
            method="POST",
            payload={
                "csv_path": "examples/security_events.csv"
            },
        )
        dashboard = _read_json(f"{base_url}/cybersecurity/dashboard")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["ingested_events"] == 5
    assert result["imported_from"] == "examples/security_events.csv"
    assert dashboard["siem"]["triggered_rules"] == 1


def test_import_history_endpoint_reports_recent_imports():
    with tempfile.TemporaryDirectory() as temp_dir:
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            _read_json(
                f"{base_url}/cybersecurity/import/network-csv",
                method="POST",
                payload={
                    "csv_text": (
                        "source_ip,destination_ip,port,protocol,payload_size\n"
                        "198.51.100.91,10.0.0.91,22,SSH,150\n"
                    )
                },
            )
            history = _read_json(f"{base_url}/cybersecurity/import-history?limit=5")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert len(history["imports"]) == 1
    assert history["imports"][0]["import_type"] == "network_csv"
    assert history["imports"][0]["status"] == "success"


def test_failed_import_is_recorded_in_import_history():
    with tempfile.TemporaryDirectory() as temp_dir:
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            request = urllib.request.Request(
                f"{base_url}/cybersecurity/import/network-csv",
                data=json.dumps(
                    {"csv_text": "source_ip,destination_ip,protocol,payload_size\nbad,10.0.0.1,SSH,10\n"}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(request)
            except urllib.error.HTTPError as exc:
                assert exc.code == 400
                error_payload = json.loads(exc.read().decode("utf-8"))
            history = _read_json(f"{base_url}/cybersecurity/import-history?limit=5")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert "Missing network event fields" in error_payload["error"]
    assert history["imports"][0]["status"] == "failed"
    assert history["imports"][0]["error_message"] is not None
