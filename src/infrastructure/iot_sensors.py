"""
IoT-enabled environmental sensor monitoring.

Monitors environmental conditions (temperature, humidity, vibration, etc.)
in organisational facilities through a network of IoT sensors.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class SensorType(Enum):
    TEMPERATURE = "temperature"
    HUMIDITY = "humidity"
    VIBRATION = "vibration"
    AIR_QUALITY = "air_quality"
    PRESSURE = "pressure"
    MOTION = "motion"


class SensorStatus(Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    FAULT = "fault"
    CALIBRATING = "calibrating"


@dataclass
class SensorReading:
    sensor_id: str
    sensor_type: SensorType
    value: float
    unit: str
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    metadata: Dict = field(default_factory=dict)


@dataclass
class Alert:
    sensor_id: str
    reading: SensorReading
    message: str
    triggered_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)


class IoTSensor:
    """
    Represents a single IoT sensor monitoring an environmental metric.

    Supports configurable thresholds; readings outside the configured range
    produce alerts.
    """

    def __init__(
        self,
        sensor_id: str,
        sensor_type: SensorType,
        unit: str,
        location: str,
        min_threshold: Optional[float] = None,
        max_threshold: Optional[float] = None,
    ) -> None:
        self.sensor_id = sensor_id
        self.sensor_type = sensor_type
        self.unit = unit
        self.location = location
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.status: SensorStatus = SensorStatus.ONLINE
        self._readings: List[SensorReading] = []
        self._alerts: List[Alert] = []

    def record_reading(self, value: float) -> Optional[Alert]:
        """Record a sensor value and return an alert if a threshold is breached."""
        reading = SensorReading(
            sensor_id=self.sensor_id,
            sensor_type=self.sensor_type,
            value=value,
            unit=self.unit,
        )
        self._readings.append(reading)
        return self._check_threshold(reading)

    def _check_threshold(self, reading: SensorReading) -> Optional[Alert]:
        alert: Optional[Alert] = None
        if self.min_threshold is not None and reading.value < self.min_threshold:
            alert = Alert(
                sensor_id=self.sensor_id,
                reading=reading,
                message=(
                    f"{self.sensor_type.value} reading {reading.value}{self.unit} "
                    f"is below minimum threshold {self.min_threshold}{self.unit}"
                ),
            )
        elif self.max_threshold is not None and reading.value > self.max_threshold:
            alert = Alert(
                sensor_id=self.sensor_id,
                reading=reading,
                message=(
                    f"{self.sensor_type.value} reading {reading.value}{self.unit} "
                    f"exceeds maximum threshold {self.max_threshold}{self.unit}"
                ),
            )
        if alert:
            self._alerts.append(alert)
        return alert

    @property
    def readings(self) -> List[SensorReading]:
        return list(self._readings)

    @property
    def alerts(self) -> List[Alert]:
        return list(self._alerts)

    @property
    def latest_reading(self) -> Optional[SensorReading]:
        return self._readings[-1] if self._readings else None


class IoTSensorNetwork:
    """
    Manages a network of IoT sensors and aggregates their readings and alerts.
    """

    def __init__(self, network_id: str) -> None:
        self.network_id = network_id
        self._sensors: Dict[str, IoTSensor] = {}

    def register_sensor(self, sensor: IoTSensor) -> None:
        self._sensors[sensor.sensor_id] = sensor

    def get_sensor(self, sensor_id: str) -> IoTSensor:
        if sensor_id not in self._sensors:
            raise KeyError(f"Sensor '{sensor_id}' not found")
        return self._sensors[sensor_id]

    def record(self, sensor_id: str, value: float) -> Optional[Alert]:
        """Record a reading for a specific sensor."""
        return self.get_sensor(sensor_id).record_reading(value)

    def all_alerts(self) -> List[Alert]:
        alerts: List[Alert] = []
        for sensor in self._sensors.values():
            alerts.extend(sensor.alerts)
        return sorted(alerts, key=lambda a: a.triggered_at)

    def get_dashboard(self) -> Dict:
        status_counts: Dict[str, int] = {s.value: 0 for s in SensorStatus}
        for sensor in self._sensors.values():
            status_counts[sensor.status.value] += 1
        return {
            "network_id": self.network_id,
            "total_sensors": len(self._sensors),
            "status_breakdown": status_counts,
            "total_alerts": len(self.all_alerts()),
        }
