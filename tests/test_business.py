"""Tests for the Business Performance Monitoring modules."""

import pytest

from src.business.bi import BusinessIntelligence, ChartType, DataSet, Report
from src.business.erp import (
    BusinessProcess,
    Department,
    EnterpriseResourcePlanning,
    ProcessStatus,
)


# ---------------------------------------------------------------------------
# ERP tests
# ---------------------------------------------------------------------------

class TestERP:
    def setup_method(self):
        self.erp = EnterpriseResourcePlanning(organization="Test Org")

    def _make_process(self, pid="P001", dept=Department.FINANCE) -> BusinessProcess:
        return BusinessProcess(process_id=pid, name="Test Process", department=dept)

    def test_register_and_retrieve_process(self):
        proc = self._make_process()
        self.erp.register_process(proc)
        retrieved = self.erp.get_process("P001")
        assert retrieved.process_id == "P001"

    def test_register_duplicate_process_raises(self):
        proc = self._make_process()
        self.erp.register_process(proc)
        with pytest.raises(ValueError):
            self.erp.register_process(proc)

    def test_get_unknown_process_raises(self):
        with pytest.raises(KeyError):
            self.erp.get_process("NONEXISTENT")

    def test_process_lifecycle(self):
        proc = self._make_process()
        assert proc.status == ProcessStatus.PENDING
        proc.start()
        assert proc.status == ProcessStatus.IN_PROGRESS
        assert proc.start_time is not None
        proc.complete()
        assert proc.status == ProcessStatus.COMPLETED
        assert proc.end_time is not None
        assert proc.duration_seconds >= 0

    def test_process_failure(self):
        proc = self._make_process()
        proc.start()
        proc.fail()
        assert proc.status == ProcessStatus.FAILED

    def test_update_kpi(self):
        proc = self._make_process()
        self.erp.register_process(proc)
        self.erp.update_kpi("P001", "units_processed", 500)
        assert self.erp.get_process("P001").kpis["units_processed"] == 500

    def test_update_kpi_unknown_process_raises(self):
        with pytest.raises(KeyError):
            self.erp.update_kpi("NONEXISTENT", "kpi", 1.0)

    def test_get_processes_by_department(self):
        self.erp.register_process(self._make_process("P001", Department.FINANCE))
        self.erp.register_process(self._make_process("P002", Department.HR))
        finance = self.erp.get_processes_by_department(Department.FINANCE)
        assert len(finance) == 1
        assert finance[0].process_id == "P001"

    def test_get_processes_by_status(self):
        proc = self._make_process()
        proc.start()
        self.erp.register_process(proc)
        in_progress = self.erp.get_processes_by_status(ProcessStatus.IN_PROGRESS)
        assert len(in_progress) == 1

    def test_dashboard(self):
        self.erp.register_process(self._make_process())
        dashboard = self.erp.get_dashboard()
        assert dashboard["total_processes"] == 1
        assert dashboard["organization"] == "Test Org"


# ---------------------------------------------------------------------------
# BI tests
# ---------------------------------------------------------------------------

class TestBI:
    def setup_method(self):
        self.bi = BusinessIntelligence()

    def _make_dataset(self) -> DataSet:
        ds = DataSet(name="test_ds", columns=["category", "value"])
        ds.add_row({"category": "A", "value": 10})
        ds.add_row({"category": "B", "value": 20})
        ds.add_row({"category": "A", "value": 30})
        return ds

    def test_register_and_retrieve_dataset(self):
        ds = self._make_dataset()
        self.bi.register_dataset(ds)
        assert self.bi.get_dataset("test_ds") is ds

    def test_dataset_add_row_missing_column_raises(self):
        ds = DataSet(name="test_ds", columns=["category", "value"])
        with pytest.raises(ValueError):
            ds.add_row({"category": "A"})

    def test_dataset_add_row_unknown_column_raises(self):
        ds = DataSet(name="test_ds", columns=["category", "value"])
        with pytest.raises(ValueError):
            ds.add_row({"category": "A", "value": 10, "unexpected": 1})

    def test_get_unknown_dataset_raises(self):
        with pytest.raises(KeyError):
            self.bi.get_dataset("NONEXISTENT")

    def test_create_and_retrieve_report(self):
        ds = self._make_dataset()
        self.bi.register_dataset(ds)
        report = Report(title="Test Report", dataset=ds, chart_type=ChartType.BAR,
                        x_axis="category", y_axis="value")
        self.bi.create_report(report)
        assert self.bi.get_report("Test Report") is report

    def test_create_report_invalid_axis_raises(self):
        ds = self._make_dataset()
        self.bi.register_dataset(ds)
        report = Report(title="Bad Report", dataset=ds, chart_type=ChartType.BAR,
                        x_axis="missing", y_axis="value")
        with pytest.raises(ValueError):
            self.bi.create_report(report)

    def test_get_unknown_report_raises(self):
        with pytest.raises(KeyError):
            self.bi.get_report("NONEXISTENT")

    def test_report_summary_stats(self):
        ds = self._make_dataset()
        report = Report(title="R", dataset=ds, chart_type=ChartType.BAR,
                        x_axis="category", y_axis="value")
        stats = report.summary_stats()
        assert stats["count"] == 3
        assert stats["mean"] == 20.0
        assert stats["median"] == 20.0

    def test_report_filter(self):
        ds = self._make_dataset()
        report = Report(title="R", dataset=ds, chart_type=ChartType.BAR,
                        x_axis="category", y_axis="value")
        filtered = report.apply_filter("category", "A")
        assert len(filtered.dataset.rows) == 2
        assert all(r["category"] == "A" for r in filtered.dataset.rows)

    def test_dashboard_lists_reports(self):
        ds = self._make_dataset()
        self.bi.register_dataset(ds)
        report = Report(title="My Report", dataset=ds, chart_type=ChartType.PIE,
                        x_axis="category", y_axis="value")
        self.bi.create_report(report)
        dashboard = self.bi.get_dashboard()
        assert "My Report" in dashboard["report_titles"]

    def test_empty_report_summary_stats(self):
        ds = DataSet(name="empty", columns=["x", "y"])
        report = Report(title="Empty", dataset=ds, chart_type=ChartType.LINE,
                        x_axis="x", y_axis="y")
        stats = report.summary_stats()
        assert stats["count"] == 0
        assert stats["mean"] is None
