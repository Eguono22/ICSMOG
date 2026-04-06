"""
Workforce Analytics.

AI-powered module to analyze employee performance, productivity, and
engagement metrics across the organization.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class EngagementLevel(Enum):
    DISENGAGED = "disengaged"
    NEUTRAL = "neutral"
    ENGAGED = "engaged"
    HIGHLY_ENGAGED = "highly_engaged"


@dataclass
class EmployeeMetrics:
    employee_id: str
    name: str
    department: str
    role: str
    performance_score: float  # 0-100
    productivity_score: float  # 0-100
    engagement_score: float   # 0-100
    attendance_rate: float    # 0-1 (fraction of days present)
    tasks_completed: int = 0
    tasks_assigned: int = 0
    metadata: Dict = field(default_factory=dict)

    @property
    def task_completion_rate(self) -> Optional[float]:
        if self.tasks_assigned == 0:
            return None
        return self.tasks_completed / self.tasks_assigned

    @property
    def engagement_level(self) -> EngagementLevel:
        if self.engagement_score < 25:
            return EngagementLevel.DISENGAGED
        if self.engagement_score < 50:
            return EngagementLevel.NEUTRAL
        if self.engagement_score < 75:
            return EngagementLevel.ENGAGED
        return EngagementLevel.HIGHLY_ENGAGED

    @property
    def overall_score(self) -> float:
        return (
            self.performance_score * 0.4
            + self.productivity_score * 0.4
            + self.engagement_score * 0.2
        )


class WorkforceAnalytics:
    """
    Workforce analytics platform that aggregates employee metrics, identifies
    performance trends, and highlights areas that require attention.
    """

    _HIGH_PERFORMER_THRESHOLD = 75.0
    _LOW_PERFORMER_THRESHOLD = 40.0

    def __init__(self, organization: str) -> None:
        self.organization = organization
        self._employees: Dict[str, EmployeeMetrics] = {}

    # ------------------------------------------------------------------
    # Data ingestion
    # ------------------------------------------------------------------

    def add_employee(self, metrics: EmployeeMetrics) -> None:
        self._employees[metrics.employee_id] = metrics

    def update_employee(self, metrics: EmployeeMetrics) -> None:
        if metrics.employee_id not in self._employees:
            raise KeyError(f"Employee '{metrics.employee_id}' not found")
        self._employees[metrics.employee_id] = metrics

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def get_top_performers(self, n: int = 5) -> List[EmployeeMetrics]:
        sorted_employees = sorted(
            self._employees.values(),
            key=lambda e: e.overall_score,
            reverse=True,
        )
        return sorted_employees[:n]

    def get_low_performers(self, n: int = 5) -> List[EmployeeMetrics]:
        sorted_employees = sorted(
            self._employees.values(),
            key=lambda e: e.overall_score,
        )
        return sorted_employees[:n]

    def get_employees_by_department(self, department: str) -> List[EmployeeMetrics]:
        return [e for e in self._employees.values() if e.department == department]

    def department_summary(self, department: str) -> Dict:
        employees = self.get_employees_by_department(department)
        if not employees:
            return {"department": department, "count": 0}
        scores = [e.overall_score for e in employees]
        return {
            "department": department,
            "count": len(employees),
            "avg_overall_score": statistics.mean(scores),
            "avg_performance": statistics.mean(e.performance_score for e in employees),
            "avg_productivity": statistics.mean(e.productivity_score for e in employees),
            "avg_engagement": statistics.mean(e.engagement_score for e in employees),
        }

    def get_dashboard(self) -> Dict:
        if not self._employees:
            return {"organization": self.organization, "total_employees": 0}
        scores = [e.overall_score for e in self._employees.values()]
        engagement_counts: Dict[str, int] = {level.value: 0 for level in EngagementLevel}
        for emp in self._employees.values():
            engagement_counts[emp.engagement_level.value] += 1
        return {
            "organization": self.organization,
            "total_employees": len(self._employees),
            "avg_overall_score": statistics.mean(scores),
            "engagement_breakdown": engagement_counts,
            "high_performers": sum(
                1 for e in self._employees.values() if e.overall_score >= self._HIGH_PERFORMER_THRESHOLD
            ),
            "low_performers": sum(
                1 for e in self._employees.values() if e.overall_score <= self._LOW_PERFORMER_THRESHOLD
            ),
        }
