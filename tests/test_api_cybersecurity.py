"""Tests for the minimal cybersecurity HTTP API."""

from __future__ import annotations

import json
import threading
import tempfile
import http.cookiejar
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from src.api.cybersecurity import build_handler
from src.services.cybersecurity import CybersecurityMonitoringService
from src.storage import CybersecurityEventStore

ANALYST_HEADERS = {
    "X-Operator-Name": "analyst-1",
    "X-Operator-Key": "icsmog-demo-key",
}

ADMIN_HEADERS = {
    "X-Operator-Name": "admin",
    "X-Operator-Key": "icsmog-admin-key",
}


def _start_test_server(
    service: CybersecurityMonitoringService | None = None,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    if service is None:
        service = CybersecurityMonitoringService()
    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _read_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    data = None
    request_headers = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=data,
        headers=request_headers,
        method=method,
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def _read_json_with_opener(
    opener: urllib.request.OpenerDirector,
    url: str,
    method: str = "GET",
    payload: dict | None = None,
) -> tuple[dict, object]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with opener.open(request) as response:
        return json.loads(response.read().decode("utf-8")), response


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
    assert "Operator Controls" in html
    assert "Operator Directory" in html
    assert "Sign In" in html
    assert "Scan Inbox Directory" in html
    assert "Authentication Telemetry" in html
    assert "Auth History" in html
    assert "Only Privileged" in html
    assert "Open Investigation" in html
    assert "Quick triage is ready" in html
    assert "/cybersecurity/auth-events" in html
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


def test_auth_event_endpoint_triggers_auth_specific_rules():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = _read_json(
            f"{base_url}/cybersecurity/auth-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source": "identity-provider",
                        "username": "admin",
                        "source_ip": "198.51.100.120",
                        "auth_method": "password",
                        "result": "success",
                        "target_resource": "admin-console",
                        "is_privileged": True,
                    }
                ]
            },
        )
        dashboard = _read_json(f"{base_url}/cybersecurity/dashboard")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["auth_events"] == 1
    assert result["triggered_rules"][0]["rule"] == "privileged_public_login"
    assert dashboard["siem"]["triggered_rules"] == 1
    assert dashboard["siem"]["auth_summary"]["total_events"] == 1
    assert dashboard["siem"]["auth_summary"]["privileged_events"] == 1


def test_auth_events_endpoint_supports_filtering():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _read_json(
            f"{base_url}/cybersecurity/auth-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source": "identity-provider",
                        "username": "alice",
                        "source_ip": "198.51.100.101",
                        "auth_method": "password",
                        "result": "denied",
                        "target_resource": "admin-console",
                        "is_privileged": True,
                        "failure_reason": "disabled_account",
                    },
                    {
                        "source": "identity-provider",
                        "username": "bob",
                        "source_ip": "198.51.100.102",
                        "auth_method": "sso",
                        "result": "success",
                        "target_resource": "vpn-console",
                    },
                ]
            },
        )
        filtered = _read_json(
            f"{base_url}/cybersecurity/auth-events?username=alice&result=denied&is_privileged=true&query=disabled"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert len(filtered["auth_events"]) == 1
    assert filtered["auth_events"][0]["username"] == "alice"
    assert filtered["auth_events"][0]["failure_reason"] == "disabled_account"


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
        extended = _read_json(
            f"{base_url}/cybersecurity/alerts?destination_ip=10.0.0.10&protocol=ssh&port=22&query=access%20attempt"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert len(filtered["alerts"]) == 1
    assert filtered["alerts"][0]["threat_level"] == "high"
    assert detail["source_ip"] == "198.51.100.31"
    assert len(extended["alerts"]) == 1
    assert extended["alerts"][0]["alert_id"] == alert_id


def test_alerts_endpoint_rejects_invalid_port_filter():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        request = urllib.request.Request(
            f"{base_url}/cybersecurity/alerts?port=abc",
            method="GET",
        )
        try:
            urllib.request.urlopen(request)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            error_payload = json.loads(exc.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert "port" in error_payload["error"]


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
    assert "Investigation Timeline" in html
    assert "Related Alerts" in html
    assert "Related Auth Activity" in html
    assert "Rule Matches" in html
    assert "text/html" in content_type


def test_alert_investigation_endpoint_returns_activity_and_related_alerts():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _read_json(
            f"{base_url}/cybersecurity/network-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source_ip": "198.51.100.55",
                        "destination_ip": "10.0.0.12",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 120,
                    },
                    {
                        "source_ip": "198.51.100.55",
                        "destination_ip": "10.0.0.99",
                        "port": 80,
                        "protocol": "HTTP",
                        "payload_size": 20000,
                    },
                ]
            },
        )
        _read_json(
            f"{base_url}/cybersecurity/auth-events",
            method="POST",
            payload={
                "events": [
                    {
                        "source": "identity-provider",
                        "username": "admin",
                        "source_ip": "198.51.100.55",
                        "auth_method": "password",
                        "result": "failure",
                        "target_resource": "vpn-console",
                        "is_privileged": True,
                        "failure_reason": "bad_password",
                    }
                    for _ in range(5)
                ]
            },
        )
        alerts = _read_json(f"{base_url}/cybersecurity/alerts")
        alert_id = next(
            alert["alert_id"]
            for alert in alerts["alerts"]
            if alert["destination_ip"] == "10.0.0.12"
        )
        request = urllib.request.Request(
            f"{base_url}/cybersecurity/alerts/{alert_id}/acknowledge",
            data=json.dumps({}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                **ANALYST_HEADERS,
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(request)
        except urllib.error.HTTPError:
            pass
        investigation = _read_json(
            f"{base_url}/cybersecurity/alerts/{alert_id}/investigation"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert investigation["alert"]["alert_id"] == alert_id
    assert investigation["timeline"][0]["type"] == "triggering_event"
    assert investigation["activity_log"] == []
    assert investigation["related_alerts"][0]["source_ip"] == "198.51.100.55"
    assert investigation["related_alerts"][0]["relationship"] == "source_ip"
    assert investigation["auth_activity"][0]["source_ip"] == "198.51.100.55"
    assert investigation["auth_activity"][0]["username"] == "admin"
    assert investigation["related_rule_activity"][0]["rule"] == "brute_force_detection"


def test_alert_lifecycle_endpoints_update_status():
    with tempfile.TemporaryDirectory() as temp_dir:
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
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
            note = _read_json(
                f"{base_url}/cybersecurity/alerts/{alert_id}/notes",
                method="POST",
                payload={
                    "note": "Operator confirmed this alert during API triage."
                },
                headers=ANALYST_HEADERS,
            )
            acknowledged = _read_json(
                f"{base_url}/cybersecurity/alerts/{alert_id}/acknowledge",
                method="POST",
                payload={},
                headers=ANALYST_HEADERS,
            )
            resolved = _read_json(
                f"{base_url}/cybersecurity/alerts/{alert_id}/resolve",
                method="POST",
                payload={},
                headers=ADMIN_HEADERS,
            )
            investigation = _read_json(
                f"{base_url}/cybersecurity/alerts/{alert_id}/investigation"
            )
            audit_log = _read_json(f"{base_url}/cybersecurity/audit-log?limit=5")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    note_entries = [
        entry
        for entry in investigation["timeline"]
        if entry["type"] == "operator_action"
        and entry["details"]["action_type"] == "add_alert_note"
    ]
    assert note["action_type"] == "add_alert_note"
    assert note["details"]["note"] == "Operator confirmed this alert during API triage."
    assert acknowledged["status"] == "acknowledged"
    assert acknowledged["updated_by"] == "analyst-1"
    assert resolved["status"] == "resolved"
    assert resolved["updated_by"] == "admin"
    assert resolved["resolved_at"] is not None
    assert note_entries[0]["details"]["details"]["note"] == (
        "Operator confirmed this alert during API triage."
    )
    assert audit_log["audit_log"][0]["action_type"] == "resolve_alert"
    assert audit_log["audit_log"][0]["operator_name"] == "admin"


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
            headers=ANALYST_HEADERS,
        )
        alerts = _read_json(f"{base_url}/cybersecurity/alerts")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["ingested_events"] == 2
    assert result["imported_from"] == "inline_csv_text"
    assert result["operator_name"] == "analyst-1"
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
            headers=ANALYST_HEADERS,
        )
        dashboard = _read_json(f"{base_url}/cybersecurity/dashboard")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["ingested_events"] == 5
    assert result["imported_from"] == "examples/security_events.csv"
    assert dashboard["siem"]["triggered_rules"] == 1


def test_auth_csv_import_endpoint_accepts_file_path():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = _read_json(
            f"{base_url}/cybersecurity/import/auth-csv",
            method="POST",
            payload={
                "csv_path": "examples/auth_events.csv"
            },
            headers=ANALYST_HEADERS,
        )
        dashboard = _read_json(f"{base_url}/cybersecurity/dashboard")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["ingested_events"] == 5
    assert result["auth_events"] == 5
    assert result["imported_from"] == "examples/auth_events.csv"
    assert dashboard["siem"]["triggered_rules"] >= 1


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
                headers=ANALYST_HEADERS,
            )
            history = _read_json(f"{base_url}/cybersecurity/import-history?limit=5")
            audit_log = _read_json(f"{base_url}/cybersecurity/audit-log?limit=5")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert len(history["imports"]) == 1
    assert history["imports"][0]["import_type"] == "network_csv"
    assert history["imports"][0]["operator_name"] == "analyst-1"
    assert history["imports"][0]["status"] == "success"
    assert audit_log["audit_log"][0]["action_type"] == "import_network_csv"
    assert audit_log["audit_log"][0]["operator_name"] == "analyst-1"


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
                headers={
                    "Content-Type": "application/json",
                    **ANALYST_HEADERS,
                },
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
    assert history["imports"][0]["operator_name"] == "analyst-1"
    assert history["imports"][0]["error_message"] is not None


def test_scan_directory_endpoint_imports_and_skips_processed_files():
    with tempfile.TemporaryDirectory() as temp_dir:
        inbox = Path(temp_dir) / "inbox"
        inbox.mkdir()
        (inbox / "network_batch.csv").write_text(
            "source_ip,destination_ip,port,protocol,payload_size\n"
            "198.51.100.101,10.0.0.101,22,SSH,150\n",
            encoding="utf-8",
        )
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            first_scan = _read_json(
                f"{base_url}/cybersecurity/import/scan-directory",
                method="POST",
                payload={
                    "directory_path": str(inbox),
                    "target": "network",
                },
                headers=ANALYST_HEADERS,
            )
            second_scan = _read_json(
                f"{base_url}/cybersecurity/import/scan-directory",
                method="POST",
                payload={
                    "directory_path": str(inbox),
                    "target": "network",
                },
                headers=ANALYST_HEADERS,
            )
            history = _read_json(f"{base_url}/cybersecurity/import-history?limit=10")
            audit_log = _read_json(f"{base_url}/cybersecurity/audit-log?limit=10")
            alerts = _read_json(f"{base_url}/cybersecurity/alerts")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert first_scan["scanned_files"] == 1
    assert first_scan["imported_files"] == 1
    assert first_scan["skipped_files"] == 0
    assert first_scan["results"][0]["status"] == "imported"
    assert second_scan["imported_files"] == 0
    assert second_scan["skipped_files"] == 1
    assert second_scan["results"][0]["reason"] == "already_processed"
    assert len(history["imports"]) == 1
    assert history["imports"][0]["file_path"].endswith("network_batch.csv")
    assert alerts["alerts"][0]["source_ip"] == "198.51.100.101"
    assert audit_log["audit_log"][0]["action_type"] == "scan_csv_directory"


def test_scan_directory_endpoint_records_failed_csv_files():
    with tempfile.TemporaryDirectory() as temp_dir:
        inbox = Path(temp_dir) / "inbox"
        inbox.mkdir()
        (inbox / "broken_network.csv").write_text(
            "source_ip,destination_ip,protocol,payload_size\n"
            "198.51.100.111,10.0.0.111,SSH,150\n",
            encoding="utf-8",
        )
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            scan_result = _read_json(
                f"{base_url}/cybersecurity/import/scan-directory",
                method="POST",
                payload={
                    "directory_path": str(inbox),
                    "target": "network",
                },
                headers=ANALYST_HEADERS,
            )
            history = _read_json(f"{base_url}/cybersecurity/import-history?limit=10")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert scan_result["scanned_files"] == 1
    assert scan_result["failed_files"] == 1
    assert scan_result["results"][0]["status"] == "failed"
    assert "Missing network event fields" in scan_result["results"][0]["error"]
    assert history["imports"][0]["status"] == "failed"
    assert history["imports"][0]["file_path"].endswith("broken_network.csv")


def test_protected_operator_actions_require_credentials():
    server, thread = _start_test_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        request = urllib.request.Request(
            f"{base_url}/cybersecurity/import/network-csv",
            data=json.dumps(
                {
                    "csv_text": (
                        "source_ip,destination_ip,port,protocol,payload_size\n"
                        "198.51.100.81,10.0.0.81,22,SSH,150\n"
                    )
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
            error_payload = json.loads(exc.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert "X-Operator-Name" in error_payload["error"]


def test_login_endpoint_sets_session_cookie_for_browser_flow():
    with tempfile.TemporaryDirectory() as temp_dir:
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        try:
            login_payload, login_response = _read_json_with_opener(
                opener,
                f"{base_url}/cybersecurity/login",
                method="POST",
                payload={
                    "username": "analyst-1",
                    "api_key": "icsmog-demo-key",
                },
            )
            me_payload, _ = _read_json_with_opener(
                opener,
                f"{base_url}/cybersecurity/me",
            )
            import_payload, _ = _read_json_with_opener(
                opener,
                f"{base_url}/cybersecurity/import/network-csv",
                method="POST",
                payload={
                    "csv_text": (
                        "source_ip,destination_ip,port,protocol,payload_size\n"
                        "198.51.100.82,10.0.0.82,22,SSH,150\n"
                    )
                },
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert login_payload["operator"]["username"] == "analyst-1"
    assert "icsmog_session=" in login_response.headers.get("Set-Cookie", "")
    assert me_payload["operator"]["role"] == "analyst"
    assert import_payload["operator_name"] == "analyst-1"


def test_logout_endpoint_clears_cookie_session():
    with tempfile.TemporaryDirectory() as temp_dir:
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        try:
            _read_json_with_opener(
                opener,
                f"{base_url}/cybersecurity/login",
                method="POST",
                payload={
                    "username": "admin",
                    "api_key": "icsmog-admin-key",
                },
            )
            logout_payload, logout_response = _read_json_with_opener(
                opener,
                f"{base_url}/cybersecurity/logout",
                method="POST",
                payload={},
            )
            request = urllib.request.Request(
                f"{base_url}/cybersecurity/me",
                method="GET",
            )
            try:
                opener.open(request)
            except urllib.error.HTTPError as exc:
                assert exc.code == 401
                me_error = json.loads(exc.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert logout_payload["status"] == "logged_out"
    assert "Max-Age=0" in logout_response.headers.get("Set-Cookie", "")
    assert "X-Operator-Name" in me_error["error"]


def test_analyst_cannot_resolve_alert():
    with tempfile.TemporaryDirectory() as temp_dir:
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            _read_json(
                f"{base_url}/cybersecurity/network-events",
                method="POST",
                payload={
                    "events": [
                        {
                            "source_ip": "198.51.100.42",
                            "destination_ip": "10.0.0.52",
                            "port": 22,
                            "protocol": "SSH",
                            "payload_size": 128,
                        }
                    ]
                },
            )
            alerts = _read_json(f"{base_url}/cybersecurity/alerts")
            alert_id = alerts["alerts"][0]["alert_id"]
            request = urllib.request.Request(
                f"{base_url}/cybersecurity/alerts/{alert_id}/resolve",
                data=json.dumps({}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    **ANALYST_HEADERS,
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request)
            except urllib.error.HTTPError as exc:
                assert exc.code == 403
                error_payload = json.loads(exc.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert "cannot perform 'resolve_alert'" in error_payload["error"]


def test_admin_can_list_and_create_operator_accounts():
    with tempfile.TemporaryDirectory() as temp_dir:
        server, thread = _start_test_server(
            CybersecurityMonitoringService(
                store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
            )
        )
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            me = _read_json(
                f"{base_url}/cybersecurity/me",
                headers=ADMIN_HEADERS,
            )
            created = _read_json(
                f"{base_url}/cybersecurity/operators",
                method="POST",
                payload={
                    "username": "tier2-admin",
                    "api_key": "tier2-secret",
                    "role": "admin",
                },
                headers=ADMIN_HEADERS,
            )
            operators = _read_json(
                f"{base_url}/cybersecurity/operators",
                headers=ADMIN_HEADERS,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert me["operator"]["role"] == "admin"
    assert created["username"] == "tier2-admin"
    assert any(operator["username"] == "tier2-admin" for operator in operators["operators"])
