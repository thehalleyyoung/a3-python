"""Calculator application - main entry point."""
from operations import divide, power, safe_divide
from utils import validate_input, parse_expression


def calculate(expr: str) -> float:
    """Parse and calculate expression."""
    op, a, b = parse_expression(expr)
    
    if op == "div":
        # BUG: DIV_ZERO - no check for zero divisor
        return divide(a, b)
    elif op == "pow":
        return power(a, b)
    elif op == "safe_div":
        return safe_divide(a, b)
    else:
        raise ValueError(f"Unknown operation: {op}")


def batch_calculate(expressions: list) -> list:
    """Calculate multiple expressions."""
    results = []
    for expr in expressions:
        # BUG: BOUNDS - accessing without checking if expressions is empty
        result = calculate(expr)
        results.append(result)
    return results


def get_nth_result(results: list, n: int) -> float:
    """Get the nth result from a list."""
    # BUG: BOUNDS - no bounds check on n
    return results[n]


if __name__ == "__main__":
    print(calculate("div 10 0"))  # Will trigger DIV_ZERO
