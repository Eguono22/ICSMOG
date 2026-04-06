"""
Business Intelligence (BI) tools.

Analyzes organizational data and exposes insights through dashboards and
report generation, mirroring tools like Power BI or Tableau.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ChartType(Enum):
    BAR = "bar"
    LINE = "line"
    PIE = "pie"
    SCATTER = "scatter"
    TABLE = "table"


@dataclass
class DataSet:
    name: str
    columns: List[str]
    rows: List[Dict[str, Any]] = field(default_factory=list)

    def add_row(self, row: Dict[str, Any]) -> None:
        self.rows.append(row)

    def column_values(self, column: str) -> List[Any]:
        return [row[column] for row in self.rows if column in row]


@dataclass
class Report:
    title: str
    dataset: DataSet
    chart_type: ChartType
    x_axis: str
    y_axis: str
    filters: Dict[str, Any] = field(default_factory=dict)

    def apply_filter(self, column: str, value: Any) -> "Report":
        """Return a new filtered Report (non-destructive)."""
        filtered_rows = [
            row for row in self.dataset.rows if row.get(column) == value
        ]
        filtered_ds = DataSet(
            name=f"{self.dataset.name}_filtered",
            columns=self.dataset.columns,
            rows=filtered_rows,
        )
        return Report(
            title=f"{self.title} [{column}={value}]",
            dataset=filtered_ds,
            chart_type=self.chart_type,
            x_axis=self.x_axis,
            y_axis=self.y_axis,
            filters={**self.filters, column: value},
        )

    def summary_stats(self) -> Dict[str, Optional[float]]:
        """Compute descriptive statistics for the y-axis column."""
        values = [
            v
            for v in self.dataset.column_values(self.y_axis)
            if isinstance(v, (int, float))
        ]
        if not values:
            return {"count": 0, "mean": None, "median": None, "stdev": None}
        return {
            "count": len(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        }


class BusinessIntelligence:
    """
    BI platform that manages data sets and produces analytical reports with
    chart specifications and descriptive statistics.
    """

    def __init__(self, platform_name: str = "ICSMOG-BI") -> None:
        self.platform_name = platform_name
        self._datasets: Dict[str, DataSet] = {}
        self._reports: Dict[str, Report] = {}

    # ------------------------------------------------------------------
    # Dataset management
    # ------------------------------------------------------------------

    def register_dataset(self, dataset: DataSet) -> None:
        self._datasets[dataset.name] = dataset

    def get_dataset(self, name: str) -> DataSet:
        if name not in self._datasets:
            raise KeyError(f"Dataset '{name}' not found")
        return self._datasets[name]

    # ------------------------------------------------------------------
    # Report management
    # ------------------------------------------------------------------

    def create_report(self, report: Report) -> None:
        self._reports[report.title] = report

    def get_report(self, title: str) -> Report:
        if title not in self._reports:
            raise KeyError(f"Report '{title}' not found")
        return self._reports[title]

    def list_reports(self) -> List[str]:
        return list(self._reports.keys())

    def get_dashboard(self) -> Dict:
        return {
            "platform": self.platform_name,
            "datasets": len(self._datasets),
            "reports": len(self._reports),
            "report_titles": self.list_reports(),
        }
