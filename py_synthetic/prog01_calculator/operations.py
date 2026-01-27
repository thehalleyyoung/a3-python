"""Mathematical operations module."""


def divide(a: float, b: float) -> float:
    """Divide a by b. No safety check - caller must ensure b != 0."""
    return a / b  # DIV_ZERO if b == 0


def power(base: float, exp: int) -> float:
    """Compute base^exp."""
    result = 1
    for _ in range(exp):
        result *= base
    return result


def safe_divide(a: float, b: float) -> float:
    """Safe division with zero check."""
    if b == 0:
        return 0.0  # Safe: returns default value
    return a / b


def modulo(a: int, b: int) -> int:
    """Compute a mod b."""
    # BUG: DIV_ZERO - modulo by zero
    return a % b


def factorial(n: int) -> int:
    """Compute n!."""
    if n < 0:
        raise ValueError("Negative factorial")
    if n == 0:
        return 1
    result = 1
    for i in range(1, n + 1):
        result *= i
    return result
