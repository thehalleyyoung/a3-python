"""Task model and utilities."""
from dataclasses import dataclass
from typing import Optional, Callable
from enum import Enum


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Task:
    id: str
    name: str
    priority: int
    handler: Callable
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[str] = None
    duration: float = 0.0
    dependencies: list = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
    
    def get_dependency(self, index: int) -> str:
        """Get dependency at index."""
        # BUG: BOUNDS
        return self.dependencies[index]
    
    def get_result_length(self) -> int:
        """Get result length."""
        # BUG: NULL_PTR
        return len(self.result)


def create_task(task_id: str, name: str, priority: int, handler: Callable) -> Task:
    """Create a new task."""
    return Task(id=task_id, name=name, priority=priority, handler=handler)


def get_task_from_list(tasks: list, index: int) -> Task:
    """Get task from list."""
    # BUG: BOUNDS
    return tasks[index]


def calculate_total_priority(tasks: list) -> int:
    """Calculate sum of priorities."""
    return sum(t.priority for t in tasks)


def calculate_avg_priority(tasks: list) -> float:
    """Calculate average priority."""
    total = calculate_total_priority(tasks)
    # BUG: DIV_ZERO
    return total / len(tasks)


def filter_by_status(tasks: list, status: TaskStatus) -> list:
    """Filter tasks by status."""
    return [t for t in tasks if t.status == status]


def get_dependent_task(task: Task, dep_map: dict) -> Task:
    """Get first dependent task."""
    # BUG: NULL_PTR
    deps = dep_map.get(task.id)
    return deps[0]  # Index on None


def safe_get_result(task: Task) -> str:
    """Safely get task result."""
    if task.result is None:
        return ""
    return task.result
