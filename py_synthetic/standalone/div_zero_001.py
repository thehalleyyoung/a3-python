"""Standalone buggy function tests for DIV_ZERO detection."""

# Test 1: Direct division by zero
def divide_unsafe(a, b):
    return a / b

result1 = divide_unsafe(10, 0)
