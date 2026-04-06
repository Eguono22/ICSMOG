"""
SCADA and PLC Systems.

Monitors and controls industrial equipment and processes in real-time,
mirroring Supervisory Control and Data Acquisition (SCADA) systems.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional


class ControlMode(Enum):
    AUTOMATIC = "automatic"
    MANUAL = "manual"
    EMERGENCY = "emergency"
    MAINTENANCE = "maintenance"


class ProcessState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    ALARM = "alarm"
    FAULT = "fault"
    SHUTDOWN = "shutdown"


@dataclass
class ProcessVariable:
    tag: str
    description: str
    value: float
    unit: str
    setpoint: Optional[float] = None
    low_limit: Optional[float] = None
    high_limit: Optional[float] = None
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)

    @property
    def in_range(self) -> bool:
        if self.low_limit is not None and self.value < self.low_limit:
            return False
        if self.high_limit is not None and self.value > self.high_limit:
            return False
        return True

    @property
    def deviation_from_setpoint(self) -> Optional[float]:
        if self.setpoint is not None:
            return abs(self.value - self.setpoint)
        return None


@dataclass
class AlarmRecord:
    tag: str
    message: str
    severity: str
    state: ProcessState
    triggered_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    acknowledged: bool = False
    acknowledged_at: Optional[datetime.datetime] = None

    def acknowledge(self) -> None:
        self.acknowledged = True
        self.acknowledged_at = datetime.datetime.utcnow()


class PLCController:
    """
    Represents a Programmable Logic Controller managing a set of process
    variables and executing control logic.
    """

    def __init__(self, plc_id: str, name: str) -> None:
        self.plc_id = plc_id
        self.name = name
        self.mode: ControlMode = ControlMode.AUTOMATIC
        self._variables: Dict[str, ProcessVariable] = {}
        self._control_logic: Optional[Callable[["PLCController"], None]] = None

    def register_variable(self, pv: ProcessVariable) -> None:
        self._variables[pv.tag] = pv

    def set_control_logic(self, logic: Callable[["PLCController"], None]) -> None:
        self._control_logic = logic

    def update_variable(self, tag: str, value: float) -> None:
        if tag not in self._variables:
            raise KeyError(f"Tag '{tag}' not registered")
        self._variables[tag].value = value
        self._variables[tag].timestamp = datetime.datetime.utcnow()
        if self.mode == ControlMode.AUTOMATIC and self._control_logic:
            self._control_logic(self)

    def get_variable(self, tag: str) -> ProcessVariable:
        if tag not in self._variables:
            raise KeyError(f"Tag '{tag}' not registered")
        return self._variables[tag]

    @property
    def variables(self) -> Dict[str, ProcessVariable]:
        return dict(self._variables)


class SCADASystem:
    """
    SCADA supervisory control and data acquisition system that monitors
    multiple PLCs and process areas in an industrial environment.
    """

    def __init__(self, plant_name: str) -> None:
        self.plant_name = plant_name
        self._plcs: Dict[str, PLCController] = {}
        self._alarms: List[AlarmRecord] = []
        self._state: ProcessState = ProcessState.IDLE

    # ------------------------------------------------------------------
    # PLC management
    # ------------------------------------------------------------------

    def register_plc(self, plc: PLCController) -> None:
        self._plcs[plc.plc_id] = plc

    def get_plc(self, plc_id: str) -> PLCController:
        if plc_id not in self._plcs:
            raise KeyError(f"PLC '{plc_id}' not found")
        return self._plcs[plc_id]

    # ------------------------------------------------------------------
    # Real-time data updates
    # ------------------------------------------------------------------

    def update(self, plc_id: str, tag: str, value: float) -> Optional[AlarmRecord]:
        """Update a process variable and return an alarm if a limit is breached."""
        plc = self.get_plc(plc_id)
        plc.update_variable(tag, value)
        pv = plc.get_variable(tag)
        if not pv.in_range:
            alarm = AlarmRecord(
                tag=tag,
                message=f"Tag '{tag}' value {value}{pv.unit} is out of range",
                severity="high",
                state=ProcessState.ALARM,
            )
            self._alarms.append(alarm)
            self._state = ProcessState.ALARM
            return alarm
        return None

    # ------------------------------------------------------------------
    # Alarm management
    # ------------------------------------------------------------------

    def acknowledge_alarm(self, index: int) -> None:
        if 0 <= index < len(self._alarms):
            self._alarms[index].acknowledge()

    def get_active_alarms(self) -> List[AlarmRecord]:
        return [a for a in self._alarms if not a.acknowledged]

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> Dict:
        total_vars = sum(len(plc.variables) for plc in self._plcs.values())
        out_of_range = sum(
            1
            for plc in self._plcs.values()
            for pv in plc.variables.values()
            if not pv.in_range
        )
        return {
            "plant": self.plant_name,
            "process_state": self._state.value,
            "total_plcs": len(self._plcs),
            "total_variables": total_vars,
            "out_of_range_variables": out_of_range,
            "total_alarms": len(self._alarms),
            "active_alarms": len(self.get_active_alarms()),
        }
