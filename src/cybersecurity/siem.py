"""
Security Information and Event Management (SIEM).

Collects, correlates and analyzes security data from multiple sources in
real-time to provide a unified view of an organization's security posture.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional


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
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    raw_data: Dict = field(default_factory=dict)


@dataclass
class CorrelationRule:
    name: str
    description: str
    condition: Callable[[List[SecurityEvent]], bool]
    severity: EventSeverity = EventSeverity.WARNING


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
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_correlation(self, _new_event: SecurityEvent) -> None:
        for rule in self._correlation_rules:
            is_triggered = rule.condition(self._events)
            is_active = self._rule_active_states.get(rule.name, False)

            if is_triggered and not is_active:
                self._triggered_rules.append(
                    {
                        "rule": rule.name,
                        "description": rule.description,
                        "severity": rule.severity.value,
                        "triggered_at": datetime.datetime.utcnow().isoformat(),
                    }
                )
                self._rule_active_states[rule.name] = True
            elif not is_triggered and is_active:
                self._rule_active_states[rule.name] = False

    def _register_default_rules(self) -> None:
        def _brute_force(events: List[SecurityEvent]) -> bool:
            recent = [
                e
                for e in events
                if e.category == EventCategory.AUTHENTICATION
                and e.severity in {EventSeverity.WARNING, EventSeverity.ERROR}
            ]
            return len(recent) >= 5

        self.add_correlation_rule(
            CorrelationRule(
                name="brute_force_detection",
                description="Five or more authentication failures detected",
                condition=_brute_force,
                severity=EventSeverity.CRITICAL,
            )
        )
