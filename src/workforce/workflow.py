"""
Task and Workflow Management.

Tracks task progress, team collaboration and workflow state, mirroring tools
like Jira, Asana, or Trello.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Priority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(Enum):
    BACKLOG = "backlog"
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    IN_REVIEW = "in_review"
    DONE = "done"
    CANCELLED = "cancelled"


@dataclass
class Task:
    task_id: str
    title: str
    description: str
    assignee: Optional[str]
    priority: Priority = Priority.MEDIUM
    status: TaskStatus = TaskStatus.BACKLOG
    due_date: Optional[datetime.date] = None
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    tags: List[str] = field(default_factory=list)

    def transition(self, new_status: TaskStatus) -> None:
        self.status = new_status
        self.updated_at = datetime.datetime.utcnow()

    @property
    def is_overdue(self) -> bool:
        if self.due_date and self.status not in {TaskStatus.DONE, TaskStatus.CANCELLED}:
            return datetime.date.today() > self.due_date
        return False


@dataclass
class Sprint:
    sprint_id: str
    name: str
    start_date: datetime.date
    end_date: datetime.date
    goal: str = ""
    task_ids: List[str] = field(default_factory=list)


class WorkflowManagement:
    """
    Workflow management system for tracking tasks and sprints across teams.
    """

    def __init__(self, project_name: str) -> None:
        self.project_name = project_name
        self._tasks: Dict[str, Task] = {}
        self._sprints: Dict[str, Sprint] = {}

    # ------------------------------------------------------------------
    # Task management
    # ------------------------------------------------------------------

    def add_task(self, task: Task) -> None:
        self._tasks[task.task_id] = task

    def get_task(self, task_id: str) -> Task:
        if task_id not in self._tasks:
            raise KeyError(f"Task '{task_id}' not found")
        return self._tasks[task_id]

    def transition_task(self, task_id: str, new_status: TaskStatus) -> None:
        self.get_task(task_id).transition(new_status)

    def assign_task(self, task_id: str, assignee: str) -> None:
        task = self.get_task(task_id)
        task.assignee = assignee
        task.updated_at = datetime.datetime.utcnow()

    def get_tasks_by_assignee(self, assignee: str) -> List[Task]:
        return [t for t in self._tasks.values() if t.assignee == assignee]

    def get_tasks_by_status(self, status: TaskStatus) -> List[Task]:
        return [t for t in self._tasks.values() if t.status == status]

    def get_overdue_tasks(self) -> List[Task]:
        return [t for t in self._tasks.values() if t.is_overdue]

    # ------------------------------------------------------------------
    # Sprint management
    # ------------------------------------------------------------------

    def add_sprint(self, sprint: Sprint) -> None:
        self._sprints[sprint.sprint_id] = sprint

    def get_sprint(self, sprint_id: str) -> Sprint:
        if sprint_id not in self._sprints:
            raise KeyError(f"Sprint '{sprint_id}' not found")
        return self._sprints[sprint_id]

    def add_task_to_sprint(self, sprint_id: str, task_id: str) -> None:
        sprint = self.get_sprint(sprint_id)
        if task_id not in sprint.task_ids:
            sprint.task_ids.append(task_id)

    def get_sprint_progress(self, sprint_id: str) -> Dict:
        sprint = self.get_sprint(sprint_id)
        tasks = [self._tasks[tid] for tid in sprint.task_ids if tid in self._tasks]
        done = sum(1 for t in tasks if t.status == TaskStatus.DONE)
        return {
            "sprint": sprint.name,
            "total_tasks": len(tasks),
            "done": done,
            "completion_rate": done / len(tasks) if tasks else 0.0,
        }

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> Dict:
        status_counts: Dict[str, int] = {s.value: 0 for s in TaskStatus}
        priority_counts: Dict[str, int] = {p.value: 0 for p in Priority}
        for task in self._tasks.values():
            status_counts[task.status.value] += 1
            priority_counts[task.priority.value] += 1
        return {
            "project": self.project_name,
            "total_tasks": len(self._tasks),
            "total_sprints": len(self._sprints),
            "status_breakdown": status_counts,
            "priority_breakdown": priority_counts,
            "overdue_tasks": len(self.get_overdue_tasks()),
        }
