"""
Enterprise Resource Planning (ERP) system monitor.

Integrates and monitors core business processes such as finance, HR,
procurement and supply-chain in a single unified platform.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ProcessStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Department(Enum):
    FINANCE = "finance"
    HR = "hr"
    PROCUREMENT = "procurement"
    SUPPLY_CHAIN = "supply_chain"
    OPERATIONS = "operations"


@dataclass
class BusinessProcess:
    process_id: str
    name: str
    department: Department
    status: ProcessStatus = ProcessStatus.PENDING
    start_time: Optional[datetime.datetime] = None
    end_time: Optional[datetime.datetime] = None
    kpis: Dict[str, float] = field(default_factory=dict)

    def start(self) -> None:
        self.status = ProcessStatus.IN_PROGRESS
        self.start_time = datetime.datetime.utcnow()

    def complete(self) -> None:
        self.status = ProcessStatus.COMPLETED
        self.end_time = datetime.datetime.utcnow()

    def fail(self) -> None:
        self.status = ProcessStatus.FAILED
        self.end_time = datetime.datetime.utcnow()

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


class EnterpriseResourcePlanning:
    """
    ERP monitoring system that tracks the health and performance of core
    business processes across all departments.
    """

    def __init__(self, organization: str) -> None:
        self.organization = organization
        self._processes: Dict[str, BusinessProcess] = {}

    # ------------------------------------------------------------------
    # Process management
    # ------------------------------------------------------------------

    def register_process(self, process: BusinessProcess) -> None:
        """Register a business process with the ERP system."""
        self._processes[process.process_id] = process

    def update_kpi(self, process_id: str, kpi_name: str, value: float) -> None:
        """Update a KPI value for a registered process."""
        if process_id not in self._processes:
            raise KeyError(f"Process '{process_id}' not found")
        self._processes[process_id].kpis[kpi_name] = value

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_process(self, process_id: str) -> BusinessProcess:
        if process_id not in self._processes:
            raise KeyError(f"Process '{process_id}' not found")
        return self._processes[process_id]

    def get_processes_by_department(self, department: Department) -> List[BusinessProcess]:
        return [p for p in self._processes.values() if p.department == department]

    def get_processes_by_status(self, status: ProcessStatus) -> List[BusinessProcess]:
        return [p for p in self._processes.values() if p.status == status]

    def get_dashboard(self) -> Dict:
        """Return a consolidated ERP performance dashboard."""
        status_counts: Dict[str, int] = {s.value: 0 for s in ProcessStatus}
        dept_counts: Dict[str, int] = {d.value: 0 for d in Department}
        for proc in self._processes.values():
            status_counts[proc.status.value] += 1
            dept_counts[proc.department.value] += 1
        return {
            "organization": self.organization,
            "total_processes": len(self._processes),
            "status_breakdown": status_counts,
            "department_breakdown": dept_counts,
        }
