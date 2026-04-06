"""Tests for the Employee and Workflow Monitoring modules."""

import datetime

import pytest

from src.workforce.analytics import EmployeeMetrics, EngagementLevel, WorkforceAnalytics
from src.workforce.workflow import Priority, Sprint, Task, TaskStatus, WorkflowManagement


# ---------------------------------------------------------------------------
# Workforce analytics tests
# ---------------------------------------------------------------------------

def _make_employee(eid="E001", dept="Engineering", perf=80, prod=80, eng=80) -> EmployeeMetrics:
    return EmployeeMetrics(
        employee_id=eid,
        name=f"Employee {eid}",
        department=dept,
        role="Developer",
        performance_score=perf,
        productivity_score=prod,
        engagement_score=eng,
        attendance_rate=0.95,
        tasks_completed=8,
        tasks_assigned=10,
    )


class TestWorkforceAnalytics:
    def setup_method(self):
        self.wa = WorkforceAnalytics("Test Org")

    def test_add_and_retrieve_employee(self):
        emp = _make_employee()
        self.wa.add_employee(emp)
        assert self.wa.get_employees_by_department("Engineering")[0].employee_id == "E001"

    def test_update_employee(self):
        emp = _make_employee()
        self.wa.add_employee(emp)
        updated = _make_employee(perf=90)
        self.wa.update_employee(updated)
        dept_emps = self.wa.get_employees_by_department("Engineering")
        assert dept_emps[0].performance_score == 90

    def test_update_unknown_employee_raises(self):
        with pytest.raises(KeyError):
            self.wa.update_employee(_make_employee("UNKNOWN"))

    def test_task_completion_rate(self):
        emp = _make_employee()
        assert emp.task_completion_rate == 0.8

    def test_task_completion_rate_zero_assigned(self):
        emp = _make_employee()
        emp.tasks_assigned = 0
        assert emp.task_completion_rate is None

    def test_engagement_level_mapping(self):
        assert _make_employee(eng=10).engagement_level == EngagementLevel.DISENGAGED
        assert _make_employee(eng=40).engagement_level == EngagementLevel.NEUTRAL
        assert _make_employee(eng=60).engagement_level == EngagementLevel.ENGAGED
        assert _make_employee(eng=80).engagement_level == EngagementLevel.HIGHLY_ENGAGED

    def test_overall_score_formula(self):
        emp = _make_employee(perf=80, prod=60, eng=100)
        expected = 80 * 0.4 + 60 * 0.4 + 100 * 0.2
        assert abs(emp.overall_score - expected) < 0.001

    def test_top_performers(self):
        for i in range(5):
            self.wa.add_employee(_make_employee(eid=f"E{i:03d}", perf=50 + i * 10))
        top = self.wa.get_top_performers(n=3)
        assert len(top) == 3
        assert top[0].performance_score >= top[1].performance_score

    def test_low_performers(self):
        for i in range(5):
            self.wa.add_employee(_make_employee(eid=f"E{i:03d}", perf=50 + i * 10))
        low = self.wa.get_low_performers(n=2)
        assert len(low) == 2
        assert low[0].overall_score <= low[1].overall_score

    def test_department_summary(self):
        self.wa.add_employee(_make_employee("E001", "Engineering"))
        self.wa.add_employee(_make_employee("E002", "Engineering"))
        summary = self.wa.department_summary("Engineering")
        assert summary["count"] == 2

    def test_empty_dashboard(self):
        dashboard = self.wa.get_dashboard()
        assert dashboard["total_employees"] == 0

    def test_dashboard_with_employees(self):
        self.wa.add_employee(_make_employee())
        dashboard = self.wa.get_dashboard()
        assert dashboard["total_employees"] == 1


# ---------------------------------------------------------------------------
# Workflow management tests
# ---------------------------------------------------------------------------

def _make_task(tid="T-001", status=TaskStatus.TODO, priority=Priority.MEDIUM,
               due_days=None) -> Task:
    due = None
    if due_days is not None:
        due = datetime.date.today() + datetime.timedelta(days=due_days)
    return Task(
        task_id=tid,
        title=f"Task {tid}",
        description="A test task",
        assignee="E001",
        priority=priority,
        status=status,
        due_date=due,
    )


class TestWorkflowManagement:
    def setup_method(self):
        self.wf = WorkflowManagement("Test Project")

    def test_add_and_retrieve_task(self):
        self.wf.add_task(_make_task())
        task = self.wf.get_task("T-001")
        assert task.task_id == "T-001"

    def test_get_unknown_task_raises(self):
        with pytest.raises(KeyError):
            self.wf.get_task("NONEXISTENT")

    def test_task_transition(self):
        self.wf.add_task(_make_task())
        self.wf.transition_task("T-001", TaskStatus.IN_PROGRESS)
        assert self.wf.get_task("T-001").status == TaskStatus.IN_PROGRESS

    def test_assign_task(self):
        self.wf.add_task(_make_task())
        self.wf.assign_task("T-001", "E002")
        assert self.wf.get_task("T-001").assignee == "E002"

    def test_get_tasks_by_assignee(self):
        self.wf.add_task(_make_task("T-001"))
        self.wf.add_task(_make_task("T-002"))
        self.wf.assign_task("T-002", "E999")
        tasks = self.wf.get_tasks_by_assignee("E001")
        assert len(tasks) == 1

    def test_get_tasks_by_status(self):
        self.wf.add_task(_make_task("T-001", status=TaskStatus.TODO))
        self.wf.add_task(_make_task("T-002", status=TaskStatus.DONE))
        assert len(self.wf.get_tasks_by_status(TaskStatus.TODO)) == 1

    def test_overdue_tasks(self):
        self.wf.add_task(_make_task("T-001", status=TaskStatus.TODO, due_days=-1))
        self.wf.add_task(_make_task("T-002", status=TaskStatus.TODO, due_days=7))
        overdue = self.wf.get_overdue_tasks()
        assert len(overdue) == 1
        assert overdue[0].task_id == "T-001"

    def test_done_task_not_overdue(self):
        task = _make_task("T-001", status=TaskStatus.DONE, due_days=-1)
        assert task.is_overdue is False

    def test_sprint_progress(self):
        sprint = Sprint(
            sprint_id="S-001",
            name="Sprint 1",
            start_date=datetime.date.today(),
            end_date=datetime.date.today() + datetime.timedelta(days=14),
        )
        self.wf.add_sprint(sprint)
        self.wf.add_task(_make_task("T-001", status=TaskStatus.DONE))
        self.wf.add_task(_make_task("T-002", status=TaskStatus.TODO))
        self.wf.add_task_to_sprint("S-001", "T-001")
        self.wf.add_task_to_sprint("S-001", "T-002")
        progress = self.wf.get_sprint_progress("S-001")
        assert progress["done"] == 1
        assert progress["total_tasks"] == 2
        assert progress["completion_rate"] == 0.5

    def test_dashboard(self):
        self.wf.add_task(_make_task())
        dashboard = self.wf.get_dashboard()
        assert dashboard["total_tasks"] == 1
        assert dashboard["project"] == "Test Project"
