"""Task scheduler - main module."""
from task import Task, create_task, TaskStatus
from scheduler import Scheduler, schedule_task
from executor import Executor, run_task


class TaskManager:
    def __init__(self):
        self.tasks = []
        self.completed = []
        self.failed = []
    
    def add_task(self, task: Task):
        self.tasks.append(task)
    
    def get_task(self, index: int) -> Task:
        """Get task by index."""
        # BUG: BOUNDS
        return self.tasks[index]
    
    def get_completed(self, index: int) -> Task:
        """Get completed task."""
        # BUG: BOUNDS
        return self.completed[index]
    
    def calculate_success_rate(self) -> float:
        """Calculate task success rate."""
        total = len(self.completed) + len(self.failed)
        # BUG: DIV_ZERO
        return len(self.completed) / total


def run_tasks(tasks: list, executor: Executor):
    """Run all tasks."""
    for task in tasks:
        run_task(executor, task)


def get_highest_priority_task(tasks: list) -> Task:
    """Get task with highest priority."""
    # BUG: BOUNDS if empty
    return max(tasks, key=lambda t: t.priority)


def calculate_avg_duration(tasks: list) -> float:
    """Calculate average task duration."""
    total = sum(t.duration for t in tasks)
    # BUG: DIV_ZERO
    return total / len(tasks)


def find_task_by_name(tasks: list, name: str) -> Task:
    """Find task by name."""
    for task in tasks:
        if task.name == name:
            return task
    return None


def get_task_result(task: Task) -> str:
    """Get task result."""
    # BUG: NULL_PTR - result could be None
    return task.result.strip()
