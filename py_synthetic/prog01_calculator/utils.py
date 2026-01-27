"""Utility functions for calculator."""


def validate_input(value: str) -> bool:
    """Validate that input is a valid number string."""
    try:
        float(value)
        return True
    except ValueError:
        return False


def parse_expression(expr: str) -> tuple:
    """Parse expression like 'div 10 5' into (op, a, b)."""
    parts = expr.split()
    # BUG: BOUNDS - assumes at least 3 parts
    op = parts[0]
    a = float(parts[1])
    b = float(parts[2])
    return (op, a, b)


def format_result(value: float, precision: int = 2) -> str:
    """Format result with given precision."""
    return f"{value:.{precision}f}"


def get_operation_name(op_code: int) -> str:
    """Convert operation code to name."""
    names = ["add", "sub", "mul", "div"]
    # BUG: BOUNDS - op_code could be out of range
    return names[op_code]
