"""
Predictive Maintenance System.

Uses AI/ML techniques to monitor machinery and systems for anomalies and
predict failures before they happen, common in manufacturing environments.
"""

from __future__ import annotations

import datetime
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from src.time_utils import utc_now


class HealthStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILED = "failed"


class MaintenanceType(Enum):
    PREVENTIVE = "preventive"
    CORRECTIVE = "corrective"
    PREDICTIVE = "predictive"
    CONDITION_BASED = "condition_based"


@dataclass
class SensorData:
    machine_id: str
    temperature: float
    vibration: float
    pressure: float
    rpm: float
    timestamp: datetime.datetime = field(default_factory=utc_now)
    additional_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class MaintenanceAlert:
    machine_id: str
    health_status: HealthStatus
    anomaly_score: float
    description: str
    recommended_action: str
    triggered_at: datetime.datetime = field(default_factory=utc_now)


@dataclass
class MaintenanceRecord:
    machine_id: str
    maintenance_type: MaintenanceType
    description: str
    performed_at: datetime.datetime = field(default_factory=utc_now)
    technician: str = ""
    downtime_hours: float = 0.0


class Machine:
    """
    Represents a monitored machine with configurable normal operating ranges.
    """

    def __init__(
        self,
        machine_id: str,
        name: str,
        normal_temp_range: tuple = (20.0, 80.0),
        normal_vibration_range: tuple = (0.0, 5.0),
        normal_pressure_range: tuple = (1.0, 10.0),
        normal_rpm_range: tuple = (500.0, 3000.0),
    ) -> None:
        self.machine_id = machine_id
        self.name = name
        self.normal_temp_range = normal_temp_range
        self.normal_vibration_range = normal_vibration_range
        self.normal_pressure_range = normal_pressure_range
        self.normal_rpm_range = normal_rpm_range
        self._readings: List[SensorData] = []

    def add_reading(self, data: SensorData) -> None:
        self._readings.append(data)

    @property
    def latest_reading(self) -> Optional[SensorData]:
        return self._readings[-1] if self._readings else None

    def compute_anomaly_score(self, data: SensorData) -> float:
        """
        Compute a normalized anomaly score [0, 1] by measuring how far each
        metric deviates from its normal range.  A score > 0.5 warrants a warning;
        a score > 0.8 indicates a critical condition.
        """
        deviations = []
        for value, (lo, hi) in (
            (data.temperature, self.normal_temp_range),
            (data.vibration, self.normal_vibration_range),
            (data.pressure, self.normal_pressure_range),
            (data.rpm, self.normal_rpm_range),
        ):
            if lo <= value <= hi:
                deviations.append(0.0)
            else:
                span = hi - lo if hi != lo else 1.0
                deviation = min(abs(value - lo), abs(value - hi)) / span
                deviations.append(min(deviation, 1.0))
        return max(deviations)


class PredictiveMaintenanceSystem:
    """
    AI/ML-powered predictive maintenance system that monitors machinery and
    schedules maintenance before failures occur.
    """

    _WARNING_THRESHOLD = 0.5
    _CRITICAL_THRESHOLD = 0.8

    def __init__(self, facility: str) -> None:
        self.facility = facility
        self._machines: Dict[str, Machine] = {}
        self._alerts: List[MaintenanceAlert] = []
        self._maintenance_log: List[MaintenanceRecord] = []

    # ------------------------------------------------------------------
    # Machine registration
    # ------------------------------------------------------------------

    def register_machine(self, machine: Machine) -> None:
        self._machines[machine.machine_id] = machine

    def get_machine(self, machine_id: str) -> Machine:
        if machine_id not in self._machines:
            raise KeyError(f"Machine '{machine_id}' not found")
        return self._machines[machine_id]

    # ------------------------------------------------------------------
    # Sensor data ingestion & analysis
    # ------------------------------------------------------------------

    def ingest_sensor_data(self, data: SensorData) -> Optional[MaintenanceAlert]:
        """Ingest sensor readings and return a predictive maintenance alert if needed."""
        machine = self.get_machine(data.machine_id)
        machine.add_reading(data)
        anomaly_score = machine.compute_anomaly_score(data)
        health = self._classify_health(anomaly_score)
        if health in {HealthStatus.WARNING, HealthStatus.CRITICAL, HealthStatus.FAILED}:
            alert = MaintenanceAlert(
                machine_id=data.machine_id,
                health_status=health,
                anomaly_score=anomaly_score,
                description=f"Anomaly detected on {machine.name} (score={anomaly_score:.2f})",
                recommended_action=self._recommend_action(health),
            )
            self._alerts.append(alert)
            return alert
        return None

    def log_maintenance(self, record: MaintenanceRecord) -> None:
        self._maintenance_log.append(record)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @property
    def alerts(self) -> List[MaintenanceAlert]:
        return list(self._alerts)

    def get_machine_health(self, machine_id: str) -> HealthStatus:
        machine = self.get_machine(machine_id)
        if machine.latest_reading is None:
            return HealthStatus.HEALTHY
        score = machine.compute_anomaly_score(machine.latest_reading)
        return self._classify_health(score)

    def get_dashboard(self) -> Dict:
        health_counts: Dict[str, int] = {h.value: 0 for h in HealthStatus}
        for mid in self._machines:
            health_counts[self.get_machine_health(mid).value] += 1
        return {
            "facility": self.facility,
            "total_machines": len(self._machines),
            "health_breakdown": health_counts,
            "total_alerts": len(self._alerts),
            "maintenance_records": len(self._maintenance_log),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify_health(self, score: float) -> HealthStatus:
        if score >= 1.0:
            return HealthStatus.FAILED
        if score >= self._CRITICAL_THRESHOLD:
            return HealthStatus.CRITICAL
        if score >= self._WARNING_THRESHOLD:
            return HealthStatus.WARNING
        return HealthStatus.HEALTHY

    @staticmethod
    def _recommend_action(health: HealthStatus) -> str:
        recommendations = {
            HealthStatus.WARNING: "Schedule preventive maintenance within the next 7 days",
            HealthStatus.CRITICAL: "Inspect machine immediately and prepare for shutdown",
            HealthStatus.FAILED: "Take machine offline and perform corrective maintenance",
        }
        return recommendations.get(health, "No action required")
