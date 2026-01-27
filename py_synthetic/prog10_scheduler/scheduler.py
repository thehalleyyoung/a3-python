"""Scheduler module."""
from dataclasses import dataclass
from typing import List, Optional
from task import Task, TaskStatus


@dataclass
class ScheduleEntry:
    task: Task
    start_time: float
    end_time: Optional[float] = None


class Scheduler:
    def __init__(self, max_concurrent: int = 4):
        self.max_concurrent = max_concurrent
        self.queue = []
        self.running = []
        self.schedule = []
    
    def enqueue(self, task: Task):
        self.queue.append(task)
    
    def get_queued(self, index: int) -> Task:
        """Get queued task."""
        # BUG: BOUNDS
        return self.queue[index]
    
    def get_running(self, index: int) -> Task:
        """Get running task."""
        # BUG: BOUNDS
        return self.running[index]
    
    def get_schedule_entry(self, index: int) -> ScheduleEntry:
        """Get schedule entry."""
        # BUG: BOUNDS
        return self.schedule[index]
    
    def calculate_utilization(self) -> float:
        """Calculate scheduler utilization."""
        # BUG: DIV_ZERO
        return len(self.running) / self.max_concurrent


def schedule_task(scheduler: Scheduler, task: Task):
    """Schedule a task."""
    scheduler.enqueue(task)


def get_next_task(scheduler: Scheduler) -> Task:
    """Get next task to run."""
    if not scheduler.queue:
        return None
    return scheduler.queue.pop(0)


def calculate_wait_time(entries: list) -> float:
    """Calculate average wait time."""
    total = sum(e.start_time for e in entries)
    # BUG: DIV_ZERO
    return total / len(entries)


def get_entry_duration(entry: ScheduleEntry) -> float:
    """Calculate entry duration."""
    # BUG: NULL_PTR - end_time could be None
    return entry.end_time - entry.start_time


def find_entry_by_task(entries: list, task_id: str) -> ScheduleEntry:
    """Find schedule entry by task ID."""
    for entry in entries:
        if entry.task.id == task_id:
            return entry
    return None


def get_entry_task_name(entry: ScheduleEntry) -> str:
    """Get task name from entry."""
    # No bug - direct access
    return entry.task.name


def calculate_throughput(completed: int, time_span: float) -> float:
    """Calculate task throughput."""
    # BUG: DIV_ZERO
    return completed / time_span
