"""
Building Management System (BMS).

Controls and monitors building operations including HVAC, lighting, and
physical security systems.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class SystemType(Enum):
    HVAC = "hvac"
    LIGHTING = "lighting"
    SECURITY = "security"
    FIRE_SAFETY = "fire_safety"
    ELEVATORS = "elevators"
    ENERGY = "energy"


class OperationalStatus(Enum):
    RUNNING = "running"
    STANDBY = "standby"
    MAINTENANCE = "maintenance"
    FAULT = "fault"
    OFF = "off"


@dataclass
class BuildingSystem:
    system_id: str
    system_type: SystemType
    location: str
    status: OperationalStatus = OperationalStatus.STANDBY
    settings: Dict = field(default_factory=dict)
    last_updated: datetime.datetime = field(default_factory=datetime.datetime.utcnow)

    def update_setting(self, key: str, value) -> None:
        self.settings[key] = value
        self.last_updated = datetime.datetime.utcnow()

    def set_status(self, status: OperationalStatus) -> None:
        self.status = status
        self.last_updated = datetime.datetime.utcnow()


@dataclass
class MaintenanceRecord:
    system_id: str
    description: str
    performed_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    performed_by: str = "system"
    notes: str = ""


class BuildingManagementSystem:
    """
    BMS that provides unified monitoring and control of all building subsystems.
    """

    def __init__(self, building_name: str) -> None:
        self.building_name = building_name
        self._systems: Dict[str, BuildingSystem] = {}
        self._maintenance_log: List[MaintenanceRecord] = []

    # ------------------------------------------------------------------
    # System management
    # ------------------------------------------------------------------

    def register_system(self, system: BuildingSystem) -> None:
        self._systems[system.system_id] = system

    def get_system(self, system_id: str) -> BuildingSystem:
        if system_id not in self._systems:
            raise KeyError(f"System '{system_id}' not found")
        return self._systems[system_id]

    def update_system_setting(self, system_id: str, key: str, value) -> None:
        self.get_system(system_id).update_setting(key, value)

    def set_system_status(self, system_id: str, status: OperationalStatus) -> None:
        self.get_system(system_id).set_status(status)

    # ------------------------------------------------------------------
    # Maintenance log
    # ------------------------------------------------------------------

    def log_maintenance(self, record: MaintenanceRecord) -> None:
        self._maintenance_log.append(record)

    def get_maintenance_history(self, system_id: Optional[str] = None) -> List[MaintenanceRecord]:
        if system_id:
            return [r for r in self._maintenance_log if r.system_id == system_id]
        return list(self._maintenance_log)

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> Dict:
        status_counts: Dict[str, int] = {s.value: 0 for s in OperationalStatus}
        type_counts: Dict[str, int] = {t.value: 0 for t in SystemType}
        for sys in self._systems.values():
            status_counts[sys.status.value] += 1
            type_counts[sys.system_type.value] += 1
        fault_systems = [s.system_id for s in self._systems.values() if s.status == OperationalStatus.FAULT]
        return {
            "building": self.building_name,
            "total_systems": len(self._systems),
            "status_breakdown": status_counts,
            "system_types": type_counts,
            "fault_systems": fault_systems,
            "maintenance_records": len(self._maintenance_log),
        }
