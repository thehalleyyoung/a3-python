"""Test harness for task scheduler - triggers buggy functions."""


def test_get_task_oob():
    """Get task at bad index - triggers BOUNDS."""
    tasks = []
    index = 0
    # BUG: BOUNDS
    return tasks[index]


def test_get_completed_oob():
    """Get completed task at bad index - triggers BOUNDS."""
    completed = []
    index = 0
    # BUG: BOUNDS
    return completed[index]


def test_calculate_success_rate_zero():
    """Calculate rate with zero total - triggers DIV_ZERO."""
    completed = []
    failed = []
    total = len(completed) + len(failed)
    # BUG: DIV_ZERO
    return len(completed) / total


def test_get_highest_priority_task_empty():
    """Get highest priority from empty - triggers BOUNDS."""
    tasks = []
    # BUG: BOUNDS (max of empty sequence)
    return max(tasks, key=lambda t: t.get('priority', 0))


def test_calculate_avg_duration_empty():
    """Calculate avg with empty tasks - triggers DIV_ZERO."""
    tasks = []
    total = sum(t.get('duration', 0) for t in tasks)
    # BUG: DIV_ZERO
    return total / len(tasks)


def test_get_task_result_none():
    """Get result when None - triggers NULL_PTR."""
    class Task:
        result = None
    task = Task()
    # BUG: NULL_PTR
    return task.result.strip()


def test_get_dependency_oob():
    """Get dependency at bad index - triggers BOUNDS."""
    dependencies = []
    index = 0
    # BUG: BOUNDS
    return dependencies[index]


def test_get_result_length_none():
    """Get length of None result - triggers NULL_PTR."""
    result = None
    # BUG: NULL_PTR
    return len(result)


def test_get_task_from_list_oob():
    """Get task from empty list - triggers BOUNDS."""
    tasks = []
    index = 0
    # BUG: BOUNDS
    return tasks[index]


def test_calculate_avg_priority_empty():
    """Calculate avg with empty tasks - triggers DIV_ZERO."""
    tasks = []
    total = sum(t.get('priority', 0) for t in tasks)
    # BUG: DIV_ZERO
    return total / len(tasks)


def test_get_dependent_task_none():
    """Get dependent when missing - triggers NULL_PTR."""
    dep_map = {}
    task_id = "nonexistent"
    deps = dep_map.get(task_id)
    # BUG: NULL_PTR
    return deps[0]


def test_get_queued_oob():
    """Get queued task at bad index - triggers BOUNDS."""
    queue = []
    index = 0
    # BUG: BOUNDS
    return queue[index]


def test_get_running_oob():
    """Get running task at bad index - triggers BOUNDS."""
    running = []
    index = 0
    # BUG: BOUNDS
    return running[index]


def test_get_schedule_entry_oob():
    """Get schedule entry at bad index - triggers BOUNDS."""
    schedule = []
    index = 0
    # BUG: BOUNDS
    return schedule[index]


def test_calculate_utilization_zero():
    """Calculate utilization with zero max - triggers DIV_ZERO."""
    running_count = 2
    max_concurrent = 0
    # BUG: DIV_ZERO
    return running_count / max_concurrent


def test_calculate_wait_time_empty():
    """Calculate wait with empty entries - triggers DIV_ZERO."""
    entries = []
    total = sum(e.get('start_time', 0) for e in entries)
    # BUG: DIV_ZERO
    return total / len(entries)


def test_get_entry_duration_none():
    """Get duration when end_time is None - triggers NULL_PTR."""
    class Entry:
        start_time = 0.0
        end_time = None
    entry = Entry()
    # BUG: NULL_PTR (None - float)
    return entry.end_time - entry.start_time


def test_calculate_throughput_zero():
    """Calculate throughput with zero span - triggers DIV_ZERO."""
    completed = 10
    time_span = 0.0
    # BUG: DIV_ZERO
    return completed / time_span


def test_executor_get_result_oob():
    """Get result at bad index - triggers BOUNDS."""
    results = []
    index = 0
    # BUG: BOUNDS
    return results[index]


def test_executor_get_active_task_oob():
    """Get active task at bad index - triggers BOUNDS."""
    active_tasks = []
    index = 0
    # BUG: BOUNDS
    return active_tasks[index]


def test_executor_calculate_success_rate_empty():
    """Calculate rate with empty results - triggers DIV_ZERO."""
    results = []
    successful = sum(1 for r in results if r.get('success', False))
    # BUG: DIV_ZERO
    return successful / len(results)


def test_get_task_output_none():
    """Get output when None - triggers NULL_PTR."""
    class Result:
        output = None
    result = Result()
    # BUG: NULL_PTR
    return result.output.strip()


def test_get_task_error_none():
    """Get error when None - triggers NULL_PTR."""
    class Result:
        error = None
    result = Result()
    # BUG: NULL_PTR
    return result.error.lower()


def test_calculate_avg_execution_time_empty():
    """Calculate avg with empty times - triggers DIV_ZERO."""
    times = []
    total = sum(times)
    # BUG: DIV_ZERO
    return total / len(times)


def test_get_result_at_oob():
    """Get result at bad index - triggers BOUNDS."""
    results = []
    index = 0
    # BUG: BOUNDS
    return results[index]


# Run tests
if __name__ == "__main__":
    try:
        test_calculate_success_rate_zero()
    except ZeroDivisionError:
        pass
