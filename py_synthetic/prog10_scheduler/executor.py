"""Task executor module."""
from dataclasses import dataclass
from typing import List, Optional
from task import Task, TaskStatus


@dataclass
class ExecutionResult:
    task_id: str
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None


class Executor:
    def __init__(self, worker_count: int = 2):
        self.worker_count = worker_count
        self.results = []
        self.active_tasks = []
    
    def get_result(self, index: int) -> ExecutionResult:
        """Get result by index."""
        # BUG: BOUNDS
        return self.results[index]
    
    def get_active_task(self, index: int) -> Task:
        """Get active task."""
        # BUG: BOUNDS
        return self.active_tasks[index]
    
    def calculate_success_rate(self) -> float:
        """Calculate execution success rate."""
        successful = sum(1 for r in self.results if r.success)
        # BUG: DIV_ZERO
        return successful / len(self.results)


def run_task(executor: Executor, task: Task):
    """Execute a task."""
    try:
        result = task.handler()
        task.status = TaskStatus.COMPLETED
        task.result = str(result)
        executor.results.append(ExecutionResult(task.id, True, str(result)))
    except Exception as e:
        task.status = TaskStatus.FAILED
        executor.results.append(ExecutionResult(task.id, False, error=str(e)))


def get_task_output(result: ExecutionResult) -> str:
    """Get task output."""
    # BUG: NULL_PTR
    return result.output.strip()


def get_task_error(result: ExecutionResult) -> str:
    """Get task error."""
    # BUG: NULL_PTR
    return result.error.lower()


def calculate_avg_execution_time(times: list) -> float:
    """Calculate average execution time."""
    total = sum(times)
    # BUG: DIV_ZERO
    return total / len(times)


def get_result_at(results: list, index: int) -> ExecutionResult:
    """Get result at index."""
    # BUG: BOUNDS
    return results[index]


def filter_successful(results: list) -> list:
    """Filter successful results."""
    return [r for r in results if r.success]


def get_first_error(results: list) -> ExecutionResult:
    """Get first failed result."""
    for r in results:
        if not r.success:
            return r
    return None
