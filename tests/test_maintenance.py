"""Tests for the Predictive Maintenance and Operational Monitoring modules."""

import pytest

from src.maintenance.predictive import (
    HealthStatus,
    Machine,
    MaintenanceRecord,
    MaintenanceType,
    PredictiveMaintenanceSystem,
    SensorData,
)
from src.maintenance.scada import (
    AlarmRecord,
    ControlMode,
    PLCController,
    ProcessState,
    ProcessVariable,
    SCADASystem,
)


# ---------------------------------------------------------------------------
# Predictive maintenance tests
# ---------------------------------------------------------------------------

def _make_sensor_data(machine_id="M-001", temp=50.0, vib=2.0, pres=5.0, rpm=1500.0) -> SensorData:
    return SensorData(machine_id=machine_id, temperature=temp, vibration=vib,
                      pressure=pres, rpm=rpm)


class TestMachine:
    def setup_method(self):
        self.machine = Machine(
            machine_id="M-001",
            name="Test Machine",
            normal_temp_range=(20.0, 60.0),
            normal_vibration_range=(0.0, 5.0),
            normal_pressure_range=(1.0, 10.0),
            normal_rpm_range=(500.0, 3000.0),
        )

    def test_healthy_reading_gives_zero_score(self):
        data = _make_sensor_data()
        score = self.machine.compute_anomaly_score(data)
        assert score == 0.0

    def test_out_of_range_temp_increases_score(self):
        data = _make_sensor_data(temp=100.0)
        score = self.machine.compute_anomaly_score(data)
        assert score > 0.0

    def test_score_capped_at_one(self):
        data = _make_sensor_data(temp=10000.0)
        score = self.machine.compute_anomaly_score(data)
        assert score <= 1.0

    def test_readings_stored(self):
        data = _make_sensor_data()
        self.machine.add_reading(data)
        assert self.machine.latest_reading is data


class TestPredictiveMaintenance:
    def setup_method(self):
        self.pms = PredictiveMaintenanceSystem("Test Facility")
        self.machine = Machine("M-001", "CNC Mill", normal_temp_range=(20.0, 60.0))
        self.pms.register_machine(self.machine)

    def test_healthy_data_no_alert(self):
        data = _make_sensor_data()
        alert = self.pms.ingest_sensor_data(data)
        assert alert is None

    def test_critical_temperature_triggers_alert(self):
        data = _make_sensor_data(temp=200.0)
        alert = self.pms.ingest_sensor_data(data)
        assert alert is not None
        assert alert.health_status in {HealthStatus.WARNING, HealthStatus.CRITICAL, HealthStatus.FAILED}

    def test_get_machine_health_with_no_readings(self):
        health = self.pms.get_machine_health("M-001")
        assert health == HealthStatus.HEALTHY

    def test_get_machine_health_after_reading(self):
        self.pms.ingest_sensor_data(_make_sensor_data())
        health = self.pms.get_machine_health("M-001")
        assert health == HealthStatus.HEALTHY

    def test_unknown_machine_raises(self):
        with pytest.raises(KeyError):
            self.pms.get_machine("NONEXISTENT")

    def test_maintenance_log(self):
        record = MaintenanceRecord(
            machine_id="M-001",
            maintenance_type=MaintenanceType.PREVENTIVE,
            description="Oil change",
        )
        self.pms.log_maintenance(record)
        dashboard = self.pms.get_dashboard()
        assert dashboard["maintenance_records"] == 1

    def test_dashboard(self):
        dashboard = self.pms.get_dashboard()
        assert dashboard["total_machines"] == 1
        assert dashboard["facility"] == "Test Facility"

    def test_alert_stored(self):
        data = _make_sensor_data(temp=200.0)
        self.pms.ingest_sensor_data(data)
        assert len(self.pms.alerts) >= 1


# ---------------------------------------------------------------------------
# SCADA tests
# ---------------------------------------------------------------------------

def _make_pv(tag="TEMP", value=100.0, lo=80.0, hi=120.0) -> ProcessVariable:
    return ProcessVariable(tag=tag, description="Test PV", value=value, unit="°C",
                           low_limit=lo, high_limit=hi)


class TestPLC:
    def setup_method(self):
        self.plc = PLCController("PLC-01", "Test PLC")
        self.plc.register_variable(_make_pv())

    def test_update_variable(self):
        self.plc.update_variable("TEMP", 90.0)
        assert self.plc.get_variable("TEMP").value == 90.0

    def test_update_unknown_variable_raises(self):
        with pytest.raises(KeyError):
            self.plc.update_variable("NONEXISTENT", 1.0)

    def test_get_variable_in_range(self):
        pv = self.plc.get_variable("TEMP")
        assert pv.in_range is True

    def test_variable_out_of_range(self):
        self.plc.update_variable("TEMP", 150.0)
        pv = self.plc.get_variable("TEMP")
        assert pv.in_range is False

    def test_deviation_from_setpoint(self):
        pv = ProcessVariable(tag="FLOW", description="Flow", value=10.0, unit="L/s", setpoint=8.0)
        assert pv.deviation_from_setpoint == 2.0

    def test_no_setpoint_returns_none(self):
        pv = _make_pv()
        assert pv.deviation_from_setpoint is None

    def test_control_logic_executes_on_update(self):
        called = []
        self.plc.set_control_logic(lambda plc: called.append(True))
        self.plc.update_variable("TEMP", 100.0)
        assert len(called) == 1


class TestSCADA:
    def setup_method(self):
        self.scada = SCADASystem("Test Plant")
        self.plc = PLCController("PLC-01", "Boiler")
        self.plc.register_variable(_make_pv())
        self.scada.register_plc(self.plc)

    def test_normal_update_no_alarm(self):
        alarm = self.scada.update("PLC-01", "TEMP", 100.0)
        assert alarm is None

    def test_out_of_range_update_creates_alarm(self):
        alarm = self.scada.update("PLC-01", "TEMP", 150.0)
        assert alarm is not None
        assert "out of range" in alarm.message

    def test_unknown_plc_raises(self):
        with pytest.raises(KeyError):
            self.scada.update("NONEXISTENT", "TEMP", 100.0)

    def test_acknowledge_alarm(self):
        self.scada.update("PLC-01", "TEMP", 150.0)
        self.scada.acknowledge_alarm(0)
        assert self.scada.get_active_alarms() == []

    def test_active_alarms(self):
        self.scada.update("PLC-01", "TEMP", 150.0)
        active = self.scada.get_active_alarms()
        assert len(active) == 1

    def test_dashboard(self):
        dashboard = self.scada.get_dashboard()
        assert dashboard["plant"] == "Test Plant"
        assert dashboard["total_plcs"] == 1
