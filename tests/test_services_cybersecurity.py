"""Tests for reusable cybersecurity service workflows."""

import tempfile
import uuid
from pathlib import Path

from src.cybersecurity.ids_ips import NetworkEvent
from src.cybersecurity.siem import (
    AuthenticationEvent,
    AuthenticationResult,
    EventCategory,
    EventSeverity,
    SecurityEvent,
)
from src.services.cybersecurity import (
    CybersecurityMonitoringService,
    build_sample_auth_events,
    build_sample_network_events,
    build_sample_security_events,
    process_auth_events,
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


def test_sample_auth_events_match_demo_expectations():
    events = build_sample_auth_events()

    assert len(events) == 5
    assert all(event.username == "admin" for event in events)
    assert all(event.result == AuthenticationResult.FAILURE for event in events)


def test_sample_security_events_trigger_default_rule():
    events = build_sample_security_events()

    assert len(events) == 5
    assert all(event.category == EventCategory.AUTHENTICATION for event in events)
    assert all(event.raw_data["username"] == "admin" for event in events)


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


def test_process_auth_events_returns_dashboard_and_auth_summary():
    result = process_auth_events(
        [
            AuthenticationEvent(
                source="identity-provider",
                username="admin",
                source_ip="198.51.100.50",
                auth_method="password",
                result=AuthenticationResult.SUCCESS,
                target_resource="admin-console",
                is_privileged=True,
            )
        ]
    )

    assert result["auth_events"] == 1
    assert result["dashboard"]["total_events"] == 1
    assert result["triggered_rules"][0]["rule"] == "privileged_public_login"


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


def test_stateful_service_ingests_auth_payload_with_explainable_rules():
    service = CybersecurityMonitoringService()

    result = service.ingest_auth_payload(
        {
            "events": [
                {
                    "source": "identity-provider",
                    "username": "disabled-admin",
                    "source_ip": "203.0.113.45",
                    "auth_method": "password",
                    "result": "denied",
                    "target_resource": "vpn-console",
                    "is_privileged": True,
                    "failure_reason": "disabled_account",
                }
            ]
        }
    )

    triggered_rule_names = {rule["rule"] for rule in result["triggered_rules"]}

    assert result["auth_events"] == 1
    assert result["dashboard"]["total_events"] == 1
    assert "disabled_account_activity" in triggered_rule_names


def test_dashboard_includes_auth_summary_after_auth_ingestion():
    service = CybersecurityMonitoringService()

    service.ingest_auth_payload(
        {
            "events": [
                {
                    "source": "identity-provider",
                    "username": "alice",
                    "source_ip": "198.51.100.70",
                    "auth_method": "password",
                    "result": "failure",
                    "target_resource": "admin-console",
                    "failure_reason": "bad_password",
                },
                {
                    "source": "identity-provider",
                    "username": "alice",
                    "source_ip": "198.51.100.70",
                    "auth_method": "password",
                    "result": "denied",
                    "target_resource": "admin-console",
                    "failure_reason": "disabled_account",
                    "is_privileged": True,
                },
            ]
        }
    )

    dashboard = service.get_dashboard()
    auth_summary = dashboard["siem"]["auth_summary"]

    assert auth_summary["total_events"] == 2
    assert auth_summary["result_breakdown"]["failure"] == 1
    assert auth_summary["result_breakdown"]["denied"] == 1
    assert auth_summary["privileged_events"] == 1
    assert auth_summary["top_usernames"][0]["label"] == "alice"


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


def test_service_records_operator_audit_history():
    with tempfile.TemporaryDirectory() as temp_dir:
        store = CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
        service = CybersecurityMonitoringService(store=store)
        service.ingest_network_payload(
            {
                "events": [
                    {
                        "source_ip": "203.0.113.130",
                        "destination_ip": "10.0.0.30",
                        "port": 22,
                        "protocol": "SSH",
                        "payload_size": 111,
                    }
                ]
            }
        )
        alert_id = service.get_alerts()[0]["alert_id"]
        service.acknowledge_alert(alert_id, operator_name="soc-lead")
        service.import_network_csv(
            {
                "csv_text": (
                    "source_ip,destination_ip,port,protocol,payload_size\n"
                    "198.51.100.99,10.0.0.99,22,SSH,144\n"
                )
            },
            operator_name="soc-lead",
        )

        audit_log = service.get_audit_log(limit=5)
        history = service.get_import_history(limit=5)

    assert audit_log[0]["operator_name"] == "soc-lead"
    assert history[0]["operator_name"] == "soc-lead"


def test_service_imports_auth_csv_and_preserves_context():
    service = CybersecurityMonitoringService()

    result = service.import_auth_csv(
        {
            "csv_text": (
                "source,username,source_ip,auth_method,result,target_resource,is_privileged,failure_reason\n"
                "identity-provider,alice,198.51.100.77,password,denied,admin-console,true,disabled_account\n"
            )
        },
        operator_name="soc-lead",
    )

    rules = service.get_triggered_rules()
    auth_event = service.siem.get_events()[0]

    assert result["auth_events"] == 1
    assert rules[0]["rule"] == "disabled_account_activity"
    assert auth_event.raw_data["username"] == "alice"
    assert auth_event.raw_data["is_privileged"] is True


def test_service_filters_auth_events_in_memory():
    service = CybersecurityMonitoringService()
    service.ingest_auth_payload(
        {
            "events": [
                {
                    "source": "identity-provider",
                    "username": "alice",
                    "source_ip": "198.51.100.77",
                    "auth_method": "password",
                    "result": "failure",
                    "target_resource": "admin-console",
                    "failure_reason": "bad_password",
                },
                {
                    "source": "identity-provider",
                    "username": "bob",
                    "source_ip": "198.51.100.88",
                    "auth_method": "sso",
                    "result": "success",
                    "target_resource": "vpn-console",
                    "is_privileged": True,
                },
            ]
        }
    )

    filtered = service.get_auth_events(
        username="bob",
        result="success",
        is_privileged=True,
    )

    assert len(filtered) == 1
    assert filtered[0]["username"] == "bob"
    assert filtered[0]["auth_method"] == "sso"


def test_service_filters_persisted_auth_events_by_first_class_fields():
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    db_path = data_dir / f"test-auth-events-{uuid.uuid4().hex}.db"
    try:
        service = CybersecurityMonitoringService(
            store=CybersecurityEventStore(str(db_path))
        )
        service.ingest_auth_payload(
            {
                "events": [
                    {
                        "source": "identity-provider",
                        "username": "alice",
                        "source_ip": "198.51.100.90",
                        "auth_method": "password",
                        "result": "denied",
                        "target_resource": "admin-console",
                        "failure_reason": "disabled_account",
                        "is_privileged": True,
                    },
                    {
                        "source": "identity-provider",
                        "username": "carol",
                        "source_ip": "198.51.100.91",
                        "auth_method": "sso",
                        "result": "success",
                        "target_resource": "vpn-console",
                    },
                ]
            }
        )

        filtered = service.get_auth_events(
            failure_reason="disabled_account",
            is_privileged=True,
            query="alice",
        )
    finally:
        db_path.unlink(missing_ok=True)

    assert len(filtered) == 1
    assert filtered[0]["username"] == "alice"
    assert filtered[0]["result"] == "denied"


def test_service_builds_alert_investigation_context():
    service = CybersecurityMonitoringService()
    service.ingest_network_payload(
        {
            "events": [
                {
                    "source_ip": "203.0.113.140",
                    "destination_ip": "10.0.0.41",
                    "port": 22,
                    "protocol": "SSH",
                    "payload_size": 110,
                },
                {
                    "source_ip": "203.0.113.140",
                    "destination_ip": "10.0.0.88",
                    "port": 8080,
                    "protocol": "HTTP",
                    "payload_size": 25000,
                },
            ]
        }
    )
    alert_id = next(
        alert["alert_id"]
        for alert in service.get_alerts()
        if alert["destination_ip"] == "10.0.0.41"
    )

    investigation = service.get_alert_investigation(alert_id)

    assert investigation is not None
    assert investigation["alert"]["alert_id"] == alert_id
    assert investigation["activity_log"] == []
    assert investigation["related_alerts"][0]["relationship"] == "source_ip"


def test_service_builds_auth_aware_investigation_context():
    service = CybersecurityMonitoringService()
    service.ingest_network_payload(
        {
            "events": [
                {
                    "source_ip": "203.0.113.200",
                    "destination_ip": "10.0.0.90",
                    "port": 22,
                    "protocol": "SSH",
                    "payload_size": 144,
                }
            ]
        }
    )
    service.ingest_auth_payload(
        {
            "events": [
                {
                    "source": "identity-provider",
                    "username": "admin",
                    "source_ip": "203.0.113.200",
                    "auth_method": "password",
                    "result": "failure",
                    "target_resource": "vpn-console",
                    "is_privileged": True,
                    "failure_reason": "bad_password",
                }
                for _ in range(5)
            ]
        }
    )
    alert_id = service.get_alerts()[0]["alert_id"]

    investigation = service.get_alert_investigation(alert_id)

    assert investigation is not None
    assert investigation["auth_activity"][0]["source_ip"] == "203.0.113.200"
    assert investigation["auth_activity"][0]["username"] == "admin"
    assert investigation["related_rule_activity"][0]["rule"] == "brute_force_detection"
    assert investigation["related_rule_activity"][0]["relationship"] == "source_ip"


def test_service_bootstraps_and_creates_operator_accounts():
    with tempfile.TemporaryDirectory() as temp_dir:
        store = CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
        service = CybersecurityMonitoringService(store=store)

        analyst = service.authenticate_operator(
            "analyst-1",
            "icsmog-demo-key",
            required_permission="import_csv",
        )
        created = service.create_operator_account(
            {
                "username": "tier2-analyst",
                "api_key": "tier2-secret",
                "role": "analyst",
            },
            created_by="admin",
        )
        operators = service.list_operator_accounts()

    assert analyst["role"] == "analyst"
    assert created["username"] == "tier2-analyst"
    assert any(operator["username"] == "tier2-analyst" for operator in operators)
