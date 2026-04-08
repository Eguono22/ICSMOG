"""
Intrusion Detection and Prevention Systems (IDS/IPS).

Detects unauthorized access or unusual behavior in networks using rule-based
and anomaly-based detection techniques.
"""

from __future__ import annotations

import datetime
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class NetworkEvent:
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    payload_size: int
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    metadata: Dict = field(default_factory=dict)


@dataclass
class Alert:
    event: NetworkEvent
    threat_level: ThreatLevel
    description: str
    status: AlertStatus = AlertStatus.OPEN
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    resolved_at: Optional[datetime.datetime] = None

    def acknowledge(self) -> None:
        self.status = AlertStatus.ACKNOWLEDGED

    def resolve(self) -> None:
        self.status = AlertStatus.RESOLVED
        self.resolved_at = datetime.datetime.utcnow()


class IntrusionDetectionSystem:
    """
    Rule-based and anomaly-based network intrusion detection system.

    Monitors network traffic for suspicious patterns and raises alerts when
    unauthorized access or unusual behavior is detected.
    """

    # Well-known high-risk ports
    _HIGH_RISK_PORTS = {22, 23, 3389, 4444, 5900}
    # Suspicious payload threshold in bytes
    _LARGE_PAYLOAD_THRESHOLD = 10_000

    def __init__(self, name: str = "IDS-1") -> None:
        self.name = name
        self._alerts: List[Alert] = []
        self._blocklist: set = set()
        self._event_log: List[NetworkEvent] = []
        self._payload_baseline: List[int] = []
        self._anomaly_z_threshold: float = 3.0
        self._anomaly_min_events: int = 5
        self._anomaly_window_size: int = 100

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_event(self, event: NetworkEvent) -> Optional[Alert]:
        """Analyze a network event and return an alert if a threat is detected."""
        self._event_log.append(event)
        alert = self._inspect(event)
        if alert:
            self._alerts.append(alert)
        else:
            self._update_payload_baseline(event.payload_size)
        return alert

    def add_to_blocklist(self, ip: str) -> None:
        """Add an IP address to the blocklist."""
        self._blocklist.add(ip)

    def remove_from_blocklist(self, ip: str) -> None:
        """Remove an IP address from the blocklist."""
        self._blocklist.discard(ip)

    @property
    def alerts(self) -> List[Alert]:
        return list(self._alerts)

    @property
    def open_alerts(self) -> List[Alert]:
        return [a for a in self._alerts if a.status == AlertStatus.OPEN]

    def get_summary(self) -> Dict:
        """Return a summary of current detection state."""
        counts: Dict[str, int] = {level.value: 0 for level in ThreatLevel}
        for alert in self._alerts:
            counts[alert.threat_level.value] += 1
        return {
            "total_events": len(self._event_log),
            "total_alerts": len(self._alerts),
            "open_alerts": len(self.open_alerts),
            "threat_counts": counts,
            "blocklisted_ips": len(self._blocklist),
            "anomaly_detection": self.get_anomaly_config(),
        }

    def configure_anomaly_detection(
        self,
        z_threshold: float = 3.0,
        min_events: int = 5,
        window_size: int = 100,
    ) -> None:
        """Tune baseline-based anomaly detection parameters."""
        if z_threshold <= 0:
            raise ValueError("z_threshold must be > 0")
        if min_events < 2:
            raise ValueError("min_events must be >= 2")
        if window_size < min_events:
            raise ValueError("window_size must be >= min_events")
        self._anomaly_z_threshold = float(z_threshold)
        self._anomaly_min_events = int(min_events)
        self._anomaly_window_size = int(window_size)
        if len(self._payload_baseline) > self._anomaly_window_size:
            self._payload_baseline = self._payload_baseline[-self._anomaly_window_size :]

    def get_anomaly_config(self) -> Dict[str, Any]:
        return {
            "z_threshold": self._anomaly_z_threshold,
            "min_events": self._anomaly_min_events,
            "window_size": self._anomaly_window_size,
            "baseline_events": len(self._payload_baseline),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _inspect(self, event: NetworkEvent) -> Optional[Alert]:
        if event.source_ip in self._blocklist:
            return Alert(
                event=event,
                threat_level=ThreatLevel.CRITICAL,
                description=f"Traffic from blocklisted IP {event.source_ip}",
            )
        if event.port in self._HIGH_RISK_PORTS:
            return Alert(
                event=event,
                threat_level=ThreatLevel.HIGH,
                description=f"Access attempt on high-risk port {event.port}",
            )
        if event.payload_size > self._LARGE_PAYLOAD_THRESHOLD:
            return Alert(
                event=event,
                threat_level=ThreatLevel.MEDIUM,
                description=(
                    f"Unusually large payload detected: {event.payload_size} bytes"
                ),
            )
        anomaly_score = self._payload_anomaly_score(event.payload_size)
        if anomaly_score is not None:
            threat_level = (
                ThreatLevel.HIGH if anomaly_score >= (self._anomaly_z_threshold * 2) else ThreatLevel.MEDIUM
            )
            return Alert(
                event=event,
                threat_level=threat_level,
                description=(
                    "Anomalous payload size detected: "
                    f"{event.payload_size} bytes (z={anomaly_score:.2f}, "
                    f"threshold={self._anomaly_z_threshold:.2f})"
                ),
            )
        return None

    def _update_payload_baseline(self, payload_size: int) -> None:
        self._payload_baseline.append(payload_size)
        if len(self._payload_baseline) > self._anomaly_window_size:
            self._payload_baseline.pop(0)

    def _payload_anomaly_score(self, payload_size: int) -> Optional[float]:
        if len(self._payload_baseline) < self._anomaly_min_events:
            return None
        mean = sum(self._payload_baseline) / len(self._payload_baseline)
        variance = sum((x - mean) ** 2 for x in self._payload_baseline) / len(self._payload_baseline)
        std_dev = math.sqrt(variance)
        if std_dev == 0:
            if payload_size == mean:
                z_score = 0.0
            else:
                z_score = abs(payload_size - mean) / max(abs(mean), 1.0)
        else:
            z_score = abs(payload_size - mean) / std_dev
        if z_score >= self._anomaly_z_threshold:
            return z_score
        return None


class IntrusionPreventionSystem(IntrusionDetectionSystem):
    """
    Extends the IDS with active prevention capabilities.

    Automatically blocks traffic from IPs that trigger critical or high-severity
    alerts, in addition to all detection capabilities of the IDS.
    """

    _AUTO_BLOCK_LEVELS = {ThreatLevel.CRITICAL, ThreatLevel.HIGH}

    def __init__(self, name: str = "IPS-1") -> None:
        super().__init__(name=name)
        self._auto_blocked: List[str] = []

    def analyze_event(self, event: NetworkEvent) -> Optional[Alert]:
        alert = super().analyze_event(event)
        if alert and alert.threat_level in self._AUTO_BLOCK_LEVELS:
            self._auto_block(event.source_ip)
        return alert

    def _auto_block(self, ip: str) -> None:
        if ip not in self._blocklist:
            self.add_to_blocklist(ip)
            self._auto_blocked.append(ip)

    @property
    def auto_blocked_ips(self) -> List[str]:
        return list(self._auto_blocked)
