"""
Security Information and Event Management (SIEM).

Collects, correlates and analyzes security data from multiple sources in
real-time to provide a unified view of an organization's security posture.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter
from typing import Callable, Dict, List, Optional

from src.time_utils import utc_now


class EventSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventCategory(Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    SYSTEM = "system"
    APPLICATION = "application"
    DATA_ACCESS = "data_access"
    COMPLIANCE = "compliance"


@dataclass
class SecurityEvent:
    source: str
    category: EventCategory
    severity: EventSeverity
    message: str
    timestamp: datetime.datetime = field(default_factory=utc_now)
    raw_data: Dict = field(default_factory=dict)


class AuthenticationResult(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


@dataclass
class AuthenticationEvent:
    source: str
    username: str
    source_ip: str
    auth_method: str
    result: AuthenticationResult
    timestamp: datetime.datetime = field(default_factory=utc_now)
    target_resource: str | None = None
    is_privileged: bool = False
    failure_reason: str | None = None
    raw_data: Dict = field(default_factory=dict)

    def to_security_event(self) -> SecurityEvent:
        return SecurityEvent(
            source=self.source,
            category=EventCategory.AUTHENTICATION,
            severity=_auth_result_to_severity(self.result),
            message=_build_auth_message(self),
            timestamp=self.timestamp,
            raw_data={
                "username": self.username,
                "source_ip": self.source_ip,
                "auth_method": self.auth_method,
                "result": self.result.value,
                "target_resource": self.target_resource,
                "is_privileged": self.is_privileged,
                "failure_reason": self.failure_reason,
                **self.raw_data,
            },
        )


@dataclass
class CorrelationRule:
    name: str
    description: str
    condition: Callable[[List[SecurityEvent]], bool]
    severity: EventSeverity = EventSeverity.WARNING
    context_builder: Callable[[List[SecurityEvent]], Dict] | None = None


class SecurityInformationEventManagement:
    """
    SIEM system that aggregates security events from multiple sources and
    identifies threats through correlation rules.
    """

    def __init__(self, name: str = "SIEM-1") -> None:
        self.name = name
        self._events: List[SecurityEvent] = []
        self._correlation_rules: List[CorrelationRule] = []
        self._triggered_rules: List[Dict] = []
        self._rule_active_states: Dict[str, bool] = {}
        self._register_default_rules()

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_event(self, event: SecurityEvent) -> None:
        """Ingest a security event from any source."""
        self._events.append(event)
        self._run_correlation(event)

    def ingest_events(self, events: List[SecurityEvent]) -> None:
        """Batch-ingest multiple events."""
        for event in events:
            self.ingest_event(event)

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_correlation_rule(self, rule: CorrelationRule) -> None:
        """Register a new correlation rule."""
        self._correlation_rules.append(rule)
        self._rule_active_states.setdefault(rule.name, False)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_events(
        self,
        severity: Optional[EventSeverity] = None,
        category: Optional[EventCategory] = None,
        since: Optional[datetime.datetime] = None,
    ) -> List[SecurityEvent]:
        """Filter events by severity, category and/or time window."""
        result = self._events
        if severity:
            result = [e for e in result if e.severity == severity]
        if category:
            result = [e for e in result if e.category == category]
        if since:
            result = [e for e in result if e.timestamp >= since]
        return result

    def get_triggered_rules(self) -> List[Dict]:
        return list(self._triggered_rules)

    def get_dashboard(self) -> Dict:
        """Return a high-level security dashboard snapshot."""
        counts: Dict[str, int] = {sev.value: 0 for sev in EventSeverity}
        for event in self._events:
            counts[event.severity.value] += 1
        return {
            "total_events": len(self._events),
            "severity_breakdown": counts,
            "triggered_rules": len(self._triggered_rules),
            "auth_summary": _summarize_authentication_events(self._events),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_correlation(self, _new_event: SecurityEvent) -> None:
        for rule in self._correlation_rules:
            is_triggered = rule.condition(self._events)
            is_active = self._rule_active_states.get(rule.name, False)

            if is_triggered and not is_active:
                details = rule.context_builder(self._events) if rule.context_builder else {}
                self._triggered_rules.append(
                    {
                        "rule": rule.name,
                        "description": rule.description,
                        "severity": rule.severity.value,
                        "triggered_at": utc_now().isoformat(),
                        "details": details,
                    }
                )
                self._rule_active_states[rule.name] = True
            elif not is_triggered and is_active:
                self._rule_active_states[rule.name] = False

    def _register_default_rules(self) -> None:
        def _brute_force(events: List[SecurityEvent]) -> bool:
            recent = _get_failed_authentication_events(events)
            return len(recent) >= 5

        def _brute_force_context(events: List[SecurityEvent]) -> Dict:
            recent = _get_failed_authentication_events(events)
            usernames = sorted(
                {
                    str(event.raw_data.get("username"))
                    for event in recent
                    if event.raw_data.get("username")
                }
            )
            source_ips = sorted(
                {
                    str(event.raw_data.get("source_ip"))
                    for event in recent
                    if event.raw_data.get("source_ip")
                }
            )
            return {
                "failed_attempts": len(recent),
                "usernames": usernames,
                "source_ips": source_ips,
            }

        def _disabled_account(events: List[SecurityEvent]) -> bool:
            return any(
                _is_disabled_account_attempt(event)
                for event in _get_authentication_events(events)
            )

        def _disabled_account_context(events: List[SecurityEvent]) -> Dict:
            matches = [
                event
                for event in _get_authentication_events(events)
                if _is_disabled_account_attempt(event)
            ]
            return {
                "usernames": sorted(
                    {
                        str(event.raw_data.get("username"))
                        for event in matches
                        if event.raw_data.get("username")
                    }
                ),
                "source_ips": sorted(
                    {
                        str(event.raw_data.get("source_ip"))
                        for event in matches
                        if event.raw_data.get("source_ip")
                    }
                ),
            }

        def _privileged_login_from_public_ip(events: List[SecurityEvent]) -> bool:
            return any(
                _is_privileged_public_authentication(event)
                for event in _get_authentication_events(events)
            )

        def _privileged_login_context(events: List[SecurityEvent]) -> Dict:
            matches = [
                event
                for event in _get_authentication_events(events)
                if _is_privileged_public_authentication(event)
            ]
            return {
                "usernames": sorted(
                    {
                        str(event.raw_data.get("username"))
                        for event in matches
                        if event.raw_data.get("username")
                    }
                ),
                "source_ips": sorted(
                    {
                        str(event.raw_data.get("source_ip"))
                        for event in matches
                        if event.raw_data.get("source_ip")
                    }
                ),
            }

        self.add_correlation_rule(
            CorrelationRule(
                name="brute_force_detection",
                description="Five or more authentication failures detected",
                condition=_brute_force,
                severity=EventSeverity.CRITICAL,
                context_builder=_brute_force_context,
            )
        )
        self.add_correlation_rule(
            CorrelationRule(
                name="disabled_account_activity",
                description="Disabled account authentication attempt detected",
                condition=_disabled_account,
                severity=EventSeverity.ERROR,
                context_builder=_disabled_account_context,
            )
        )
        self.add_correlation_rule(
            CorrelationRule(
                name="privileged_public_login",
                description="Privileged account login succeeded from a public IP",
                condition=_privileged_login_from_public_ip,
                severity=EventSeverity.CRITICAL,
                context_builder=_privileged_login_context,
            )
        )


def _auth_result_to_severity(result: AuthenticationResult) -> EventSeverity:
    if result == AuthenticationResult.SUCCESS:
        return EventSeverity.INFO
    if result == AuthenticationResult.FAILURE:
        return EventSeverity.WARNING
    return EventSeverity.ERROR


def _build_auth_message(event: AuthenticationEvent) -> str:
    status_text = {
        AuthenticationResult.SUCCESS: "succeeded",
        AuthenticationResult.FAILURE: "failed",
        AuthenticationResult.DENIED: "was denied",
    }[event.result]
    message = (
        f"Authentication {status_text} for {event.username} via "
        f"{event.auth_method} from {event.source_ip}"
    )
    if event.target_resource:
        message += f" against {event.target_resource}"
    if event.failure_reason:
        message += f" ({event.failure_reason})"
    return message


def _get_authentication_events(events: List[SecurityEvent]) -> List[SecurityEvent]:
    return [event for event in events if event.category == EventCategory.AUTHENTICATION]


def _get_failed_authentication_events(events: List[SecurityEvent]) -> List[SecurityEvent]:
    failed_events: List[SecurityEvent] = []
    for event in _get_authentication_events(events):
        result = str(event.raw_data.get("result", "")).lower()
        if result in {"failure", "denied"}:
            failed_events.append(event)
            continue
        if event.severity in {EventSeverity.WARNING, EventSeverity.ERROR, EventSeverity.CRITICAL}:
            failed_events.append(event)
    return failed_events


def _summarize_authentication_events(events: List[SecurityEvent]) -> Dict:
    auth_events = _get_authentication_events(events)
    result_breakdown = {"success": 0, "failure": 0, "denied": 0, "unknown": 0}
    usernames: Counter[str] = Counter()
    source_ips: Counter[str] = Counter()
    auth_methods: Counter[str] = Counter()
    failure_reasons: Counter[str] = Counter()
    privileged_events = 0

    for event in auth_events:
        result = _infer_auth_result(event)
        result_breakdown[result] += 1

        username = str(event.raw_data.get("username", "")).strip()
        source_ip = str(event.raw_data.get("source_ip", "")).strip()
        auth_method = str(event.raw_data.get("auth_method", "")).strip()
        failure_reason = str(event.raw_data.get("failure_reason", "")).strip()

        if username:
            usernames[username] += 1
        if source_ip:
            source_ips[source_ip] += 1
        if auth_method:
            auth_methods[auth_method] += 1
        if failure_reason:
            failure_reasons[failure_reason] += 1
        if bool(event.raw_data.get("is_privileged")):
            privileged_events += 1

    return {
        "total_events": len(auth_events),
        "result_breakdown": result_breakdown,
        "privileged_events": privileged_events,
        "top_usernames": _counter_to_rows(usernames),
        "top_source_ips": _counter_to_rows(source_ips),
        "auth_methods": _counter_to_rows(auth_methods),
        "failure_reasons": _counter_to_rows(failure_reasons),
    }


def _counter_to_rows(counter: Counter[str], limit: int = 3) -> List[Dict[str, int | str]]:
    return [
        {"label": label, "count": count}
        for label, count in counter.most_common(limit)
    ]


def _infer_auth_result(event: SecurityEvent) -> str:
    raw_result = str(event.raw_data.get("result", "")).strip().lower()
    if raw_result in {"success", "failure", "denied"}:
        return raw_result
    if event.severity == EventSeverity.INFO:
        return "success"
    if event.severity in {EventSeverity.WARNING, EventSeverity.ERROR, EventSeverity.CRITICAL}:
        if "denied" in event.message.lower():
            return "denied"
        return "failure"
    return "unknown"


def _is_disabled_account_attempt(event: SecurityEvent) -> bool:
    failure_reason = str(event.raw_data.get("failure_reason", "")).lower()
    result = str(event.raw_data.get("result", "")).lower()
    message = event.message.lower()
    return (
        failure_reason == "disabled_account"
        or result == "denied" and "disabled" in message
        or "disabled account" in message
    )


def _is_privileged_public_authentication(event: SecurityEvent) -> bool:
    if str(event.raw_data.get("result", "")).lower() != "success":
        return False
    if not bool(event.raw_data.get("is_privileged")):
        return False
    source_ip = str(event.raw_data.get("source_ip", "")).strip()
    if not source_ip:
        return False
    try:
        return not _is_internal_ip(ipaddress.ip_address(source_ip))
    except ValueError:
        return False


def _is_internal_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if address.version == 4:
        internal_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        ]
    else:
        internal_networks = [
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("fe80::/10"),
        ]
    return any(address in network for network in internal_networks)
