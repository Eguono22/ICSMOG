"""Tests for reusable cybersecurity service workflows."""

import tempfile

from src.cybersecurity.ids_ips import NetworkEvent
from src.cybersecurity.siem import (
    EventCategory,
    EventSeverity,
    SecurityEvent,
)
from src.services.cybersecurity import (
    CybersecurityMonitoringService,
    build_sample_network_events,
    build_sample_security_events,
    process_network_events,
    process_security_events,
    run_sample_cybersecurity_scenario,
)
from src.storage import CybersecurityEventStore


def test_sample_network_events_match_demo_expectations():
    events = build_sample_network_events()

    assert len(events) == 2
    assert events[1].port == 22
    assert events[1].source_ip == "203.0.113.5"


def test_sample_security_events_trigger_default_rule():
    events = build_sample_security_events()

    assert len(events) == 5
    assert all(event.category == EventCategory.AUTHENTICATION for event in events)


def test_process_network_events_returns_alert_summary():
    result = process_network_events(
        [
            NetworkEvent(
                source_ip="198.51.100.10",
                destination_ip="10.0.0.5",
                port=22,
                protocol="SSH",
                payload_size=100,
            )
        ]
    )

    assert result["alert"] == "Access attempt on high-risk port 22"
    assert result["auto_blocked_ips"] == ["198.51.100.10"]
    assert result["summary"]["total_alerts"] == 1


def test_process_security_events_returns_dashboard_and_triggered_rules():
    result = process_security_events(
        [
            SecurityEvent(
                source="auth-service",
                category=EventCategory.AUTHENTICATION,
                severity=EventSeverity.ERROR,
                message="Login failed",
            )
            for _ in range(5)
        ]
    )

    assert result["dashboard"]["total_events"] == 5
    assert result["dashboard"]["triggered_rules"] == 1
    assert result["triggered_rules"][0]["rule"] == "brute_force_detection"


def test_run_sample_cybersecurity_scenario_preserves_main_output_shape():
    result = run_sample_cybersecurity_scenario(verbose=False)

    assert sorted(result.keys()) == ["ips", "siem"]
    assert result["ips"]["summary"]["total_events"] == 2
    assert result["siem"]["dashboard"]["total_events"] == 5


def test_stateful_service_accumulates_dashboard_state():
    service = CybersecurityMonitoringService()

    service.ingest_network_payload(
        {
            "events": [
                {
                    "source_ip": "198.51.100.30",
                    "destination_ip": "10.0.0.10",
                    "port": 22,
                    "protocol": "SSH",
                    "payload_size": 64,
                }
            ]
        }
    )
    service.ingest_security_payload(
        {
            "events": [
                {
                    "source": "auth-service",
                    "category": "authentication",
                    "severity": "error",
                    "message": "Login failed",
                }
                for _ in range(5)
            ]
        }
    )

    dashboard = service.get_dashboard()
    alerts = service.get_alerts()

    assert dashboard["ips"]["total_alerts"] == 1
    assert dashboard["siem"]["triggered_rules"] == 1
    assert alerts[0]["threat_level"] == "high"


def test_service_rehydrates_state_from_sqlite_store():
    with tempfile.TemporaryDirectory() as temp_dir:
        store = CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
        first_service = CybersecurityMonitoringService(store=store)
        first_service.ingest_network_payload(
            {
                "events": [
                    {
                        "source_ip": "203.0.113.90",
                        "destination_ip": "10.0.0.20",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 144,
                    }
                ]
            }
        )
        first_service.ingest_security_payload(
            {
                "events": [
                    {
                        "source": "auth-service",
                        "category": "authentication",
                        "severity": "error",
                        "message": "Login failed",
                    }
                    for _ in range(5)
                ]
            }
        )

        reloaded_service = CybersecurityMonitoringService(store=store)
        dashboard = reloaded_service.get_dashboard()
        alerts = reloaded_service.get_alerts()

    assert dashboard["ips"]["total_events"] == 1
    assert dashboard["ips"]["total_alerts"] == 1
    assert dashboard["siem"]["total_events"] == 5
    assert dashboard["siem"]["triggered_rules"] == 1
    assert alerts[0]["source_ip"] == "203.0.113.90"


def test_alert_lifecycle_persists_across_reloads():
    with tempfile.TemporaryDirectory() as temp_dir:
        store = CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
        service = CybersecurityMonitoringService(store=store)
        service.ingest_network_payload(
            {
                "events": [
                    {
                        "source_ip": "203.0.113.101",
                        "destination_ip": "10.0.0.21",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 222,
                    }
                ]
            }
        )
        alert_id = service.get_alerts()[0]["alert_id"]
        service.acknowledge_alert(alert_id)
        service.resolve_alert(alert_id)

        reloaded = CybersecurityMonitoringService(store=store)
        alert = reloaded.get_alert_by_id(alert_id)

    assert alert is not None
    assert alert["status"] == "resolved"
    assert alert["resolved_at"] is not None
