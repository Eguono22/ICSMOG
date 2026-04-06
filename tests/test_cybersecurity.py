"""Tests for the Network and Cybersecurity Monitoring modules."""

import pytest

from src.cybersecurity.ids_ips import (
    Alert,
    AlertStatus,
    IntrusionDetectionSystem,
    IntrusionPreventionSystem,
    NetworkEvent,
    ThreatLevel,
)
from src.cybersecurity.siem import (
    CorrelationRule,
    EventCategory,
    EventSeverity,
    SecurityEvent,
    SecurityInformationEventManagement,
)


# ---------------------------------------------------------------------------
# IDS tests
# ---------------------------------------------------------------------------

def _make_event(**kwargs) -> NetworkEvent:
    defaults = dict(
        source_ip="192.168.0.1",
        destination_ip="10.0.0.1",
        port=80,
        protocol="HTTP",
        payload_size=512,
    )
    defaults.update(kwargs)
    return NetworkEvent(**defaults)


class TestIntrusionDetectionSystem:
    def setup_method(self):
        self.ids = IntrusionDetectionSystem()

    def test_normal_event_produces_no_alert(self):
        event = _make_event()
        alert = self.ids.analyze_event(event)
        assert alert is None

    def test_high_risk_port_produces_high_alert(self):
        event = _make_event(port=22)
        alert = self.ids.analyze_event(event)
        assert alert is not None
        assert alert.threat_level == ThreatLevel.HIGH

    def test_blocklisted_ip_produces_critical_alert(self):
        self.ids.add_to_blocklist("1.2.3.4")
        event = _make_event(source_ip="1.2.3.4")
        alert = self.ids.analyze_event(event)
        assert alert is not None
        assert alert.threat_level == ThreatLevel.CRITICAL

    def test_large_payload_produces_medium_alert(self):
        event = _make_event(payload_size=15000)
        alert = self.ids.analyze_event(event)
        assert alert is not None
        assert alert.threat_level == ThreatLevel.MEDIUM

    def test_remove_from_blocklist(self):
        self.ids.add_to_blocklist("1.2.3.4")
        self.ids.remove_from_blocklist("1.2.3.4")
        event = _make_event(source_ip="1.2.3.4")
        alert = self.ids.analyze_event(event)
        assert alert is None

    def test_alert_lifecycle(self):
        event = _make_event(port=22)
        alert = self.ids.analyze_event(event)
        assert alert.status == AlertStatus.OPEN
        alert.acknowledge()
        assert alert.status == AlertStatus.ACKNOWLEDGED
        alert.resolve()
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_at is not None

    def test_summary_counts_alerts(self):
        self.ids.analyze_event(_make_event(port=22))
        self.ids.analyze_event(_make_event(port=3389))
        summary = self.ids.get_summary()
        assert summary["total_alerts"] == 2
        assert summary["open_alerts"] == 2

    def test_open_alerts_excludes_resolved(self):
        event = _make_event(port=22)
        alert = self.ids.analyze_event(event)
        alert.resolve()
        assert len(self.ids.open_alerts) == 0


class TestIntrusionPreventionSystem:
    def setup_method(self):
        self.ips = IntrusionPreventionSystem()

    def test_high_severity_triggers_auto_block(self):
        event = _make_event(port=22, source_ip="5.5.5.5")
        self.ips.analyze_event(event)
        assert "5.5.5.5" in self.ips.auto_blocked_ips

    def test_medium_severity_does_not_auto_block(self):
        event = _make_event(payload_size=20000, source_ip="6.6.6.6")
        self.ips.analyze_event(event)
        assert "6.6.6.6" not in self.ips.auto_blocked_ips

    def test_subsequent_traffic_from_auto_blocked_ip_is_critical(self):
        self.ips.analyze_event(_make_event(port=22, source_ip="7.7.7.7"))
        alert = self.ips.analyze_event(_make_event(port=80, source_ip="7.7.7.7"))
        assert alert is not None
        assert alert.threat_level == ThreatLevel.CRITICAL


# ---------------------------------------------------------------------------
# SIEM tests
# ---------------------------------------------------------------------------

def _make_security_event(**kwargs) -> SecurityEvent:
    defaults = dict(
        source="test-service",
        category=EventCategory.SYSTEM,
        severity=EventSeverity.INFO,
        message="Test event",
    )
    defaults.update(kwargs)
    return SecurityEvent(**defaults)


class TestSIEM:
    def setup_method(self):
        self.siem = SecurityInformationEventManagement()

    def test_ingest_single_event(self):
        self.siem.ingest_event(_make_security_event())
        assert self.siem.get_dashboard()["total_events"] == 1

    def test_filter_by_severity(self):
        self.siem.ingest_event(_make_security_event(severity=EventSeverity.CRITICAL))
        self.siem.ingest_event(_make_security_event(severity=EventSeverity.INFO))
        critical = self.siem.get_events(severity=EventSeverity.CRITICAL)
        assert len(critical) == 1

    def test_filter_by_category(self):
        self.siem.ingest_event(_make_security_event(category=EventCategory.AUTHENTICATION))
        self.siem.ingest_event(_make_security_event(category=EventCategory.NETWORK))
        auth_events = self.siem.get_events(category=EventCategory.AUTHENTICATION)
        assert len(auth_events) == 1

    def test_brute_force_rule_triggers_after_five_failures(self):
        for _ in range(5):
            self.siem.ingest_event(_make_security_event(
                category=EventCategory.AUTHENTICATION,
                severity=EventSeverity.ERROR,
            ))
        triggered = self.siem.get_triggered_rules()
        rule_names = [r["rule"] for r in triggered]
        assert "brute_force_detection" in rule_names

    def test_custom_correlation_rule(self):
        rule = CorrelationRule(
            name="test_rule",
            description="Fires on any critical event",
            condition=lambda events: any(e.severity == EventSeverity.CRITICAL for e in events),
        )
        self.siem.add_correlation_rule(rule)
        self.siem.ingest_event(_make_security_event(severity=EventSeverity.CRITICAL))
        triggered = [r["rule"] for r in self.siem.get_triggered_rules()]
        assert "test_rule" in triggered

    def test_dashboard_severity_counts(self):
        self.siem.ingest_event(_make_security_event(severity=EventSeverity.CRITICAL))
        self.siem.ingest_event(_make_security_event(severity=EventSeverity.WARNING))
        dashboard = self.siem.get_dashboard()
        assert dashboard["severity_breakdown"]["critical"] == 1
        assert dashboard["severity_breakdown"]["warning"] == 1

    def test_batch_ingest(self):
        events = [_make_security_event() for _ in range(3)]
        self.siem.ingest_events(events)
        assert self.siem.get_dashboard()["total_events"] == 3
