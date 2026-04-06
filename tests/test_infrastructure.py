"""Tests for the Environmental and Infrastructure Monitoring modules."""

import pytest

from src.infrastructure.bms import (
    BuildingManagementSystem,
    BuildingSystem,
    MaintenanceRecord,
    OperationalStatus,
    SystemType,
)
from src.infrastructure.iot_sensors import IoTSensor, IoTSensorNetwork, SensorType


# ---------------------------------------------------------------------------
# IoT sensor tests
# ---------------------------------------------------------------------------

class TestIoTSensor:
    def setup_method(self):
        self.sensor = IoTSensor(
            sensor_id="T-001",
            sensor_type=SensorType.TEMPERATURE,
            unit="°C",
            location="Server Room",
            min_threshold=18.0,
            max_threshold=28.0,
        )

    def test_normal_reading_produces_no_alert(self):
        alert = self.sensor.record_reading(22.0)
        assert alert is None

    def test_above_max_threshold_produces_alert(self):
        alert = self.sensor.record_reading(35.0)
        assert alert is not None
        assert "exceeds maximum threshold" in alert.message

    def test_below_min_threshold_produces_alert(self):
        alert = self.sensor.record_reading(10.0)
        assert alert is not None
        assert "below minimum threshold" in alert.message

    def test_readings_are_stored(self):
        self.sensor.record_reading(20.0)
        self.sensor.record_reading(25.0)
        assert len(self.sensor.readings) == 2

    def test_latest_reading(self):
        self.sensor.record_reading(20.0)
        self.sensor.record_reading(25.0)
        assert self.sensor.latest_reading.value == 25.0

    def test_no_latest_reading_when_empty(self):
        assert self.sensor.latest_reading is None

    def test_alerts_list(self):
        self.sensor.record_reading(22.0)  # no alert
        self.sensor.record_reading(35.0)  # alert
        assert len(self.sensor.alerts) == 1

    def test_sensor_without_thresholds_never_alerts(self):
        sensor = IoTSensor("H-001", SensorType.HUMIDITY, "%", "Warehouse")
        for value in [0, 50, 100, 200]:
            assert sensor.record_reading(value) is None


class TestIoTSensorNetwork:
    def setup_method(self):
        self.network = IoTSensorNetwork("net-1")
        self.sensor = IoTSensor("T-001", SensorType.TEMPERATURE, "°C", "Room A",
                                min_threshold=10.0, max_threshold=30.0)
        self.network.register_sensor(self.sensor)

    def test_record_normal_reading(self):
        alert = self.network.record("T-001", 20.0)
        assert alert is None

    def test_record_threshold_breach(self):
        alert = self.network.record("T-001", 50.0)
        assert alert is not None

    def test_get_unknown_sensor_raises(self):
        with pytest.raises(KeyError):
            self.network.get_sensor("NONEXISTENT")

    def test_all_alerts_aggregates(self):
        self.network.record("T-001", 50.0)
        assert len(self.network.all_alerts()) == 1

    def test_dashboard(self):
        dashboard = self.network.get_dashboard()
        assert dashboard["total_sensors"] == 1
        assert dashboard["network_id"] == "net-1"


# ---------------------------------------------------------------------------
# BMS tests
# ---------------------------------------------------------------------------

class TestBMS:
    def setup_method(self):
        self.bms = BuildingManagementSystem("Test Building")
        self.system = BuildingSystem("HVAC-01", SystemType.HVAC, "Floor 1")
        self.bms.register_system(self.system)

    def test_register_and_retrieve_system(self):
        retrieved = self.bms.get_system("HVAC-01")
        assert retrieved.system_id == "HVAC-01"

    def test_get_unknown_system_raises(self):
        with pytest.raises(KeyError):
            self.bms.get_system("NONEXISTENT")

    def test_update_system_setting(self):
        self.bms.update_system_setting("HVAC-01", "temp_setpoint", 21.0)
        assert self.bms.get_system("HVAC-01").settings["temp_setpoint"] == 21.0

    def test_set_system_status(self):
        self.bms.set_system_status("HVAC-01", OperationalStatus.RUNNING)
        assert self.bms.get_system("HVAC-01").status == OperationalStatus.RUNNING

    def test_maintenance_log(self):
        record = MaintenanceRecord(system_id="HVAC-01", description="Filter replaced", performed_by="tech1")
        self.bms.log_maintenance(record)
        history = self.bms.get_maintenance_history("HVAC-01")
        assert len(history) == 1

    def test_maintenance_history_all_systems(self):
        record1 = MaintenanceRecord(system_id="HVAC-01", description="Service A")
        record2 = MaintenanceRecord(system_id="HVAC-02", description="Service B")
        self.bms.log_maintenance(record1)
        self.bms.log_maintenance(record2)
        all_records = self.bms.get_maintenance_history()
        assert len(all_records) == 2

    def test_dashboard_fault_systems(self):
        self.bms.set_system_status("HVAC-01", OperationalStatus.FAULT)
        dashboard = self.bms.get_dashboard()
        assert "HVAC-01" in dashboard["fault_systems"]

    def test_dashboard_system_type_count(self):
        dashboard = self.bms.get_dashboard()
        assert dashboard["system_types"]["hvac"] == 1
