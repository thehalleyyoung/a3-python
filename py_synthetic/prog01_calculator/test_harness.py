"""Test harness for calculator - triggers buggy functions with symbolic inputs."""

# Import the modules being tested
from operations import divide, modulo, safe_divide, power, factorial
from utils import parse_expression, get_operation_name, validate_input, format_result


def test_divide_zero():
    """Call divide with potentially zero divisor - triggers DIV_ZERO."""
    a = 10
    b = 0  # Zero divisor
    result = divide(a, b)  # BUG: DIV_ZERO
    return result


def test_modulo_zero():
    """Call modulo with zero divisor - triggers DIV_ZERO."""
    a = 10
    b = 0  # Zero divisor
    result = modulo(a, b)  # BUG: DIV_ZERO
    return result


def test_parse_expression_short():
    """Call parse_expression with short input - triggers BOUNDS."""
    expr = "div"  # Only 1 part, needs 3
    result = parse_expression(expr)  # BUG: BOUNDS
    return result


def test_get_operation_name_oob():
    """Call get_operation_name with out-of-bounds code - triggers BOUNDS."""
    op_code = 10  # Only 4 operations defined (0-3)
    result = get_operation_name(op_code)  # BUG: BOUNDS
    return result


def test_get_nth_result_oob():
    """Call get_nth_result with out-of-bounds index - triggers BOUNDS."""
    results = [1.0, 2.0, 3.0]
    n = 10  # Out of bounds
    return results[n]  # BUG: BOUNDS


# Safe functions - should not trigger bugs
def test_safe_divide():
    """Safe divide handles zero."""
    return safe_divide(10, 0)  # SAFE


def test_power():
    """Power is safe."""
    return power(2, 10)  # SAFE


def test_factorial():
    """Factorial is safe for non-negative."""
    return factorial(5)  # SAFE


# Run tests
if __name__ == "__main__":
    # These will raise exceptions
    try:
        test_divide_zero()
    except ZeroDivisionError:
        pass
