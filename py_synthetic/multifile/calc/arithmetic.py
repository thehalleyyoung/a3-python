"""Calculator - arithmetic module with division bug and trigger."""

def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

def multiply(a, b):
    return a * b

def divide(a, b):
    return a / b  # BUG: No guard for b=0

# Trigger the bug
result = divide(10, 0)
