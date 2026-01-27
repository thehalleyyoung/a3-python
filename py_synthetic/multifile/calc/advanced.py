"""Calculator - advanced operations."""

def power(base, exp):
    result = 1
    for i in range(exp):
        result *= base
    return result

def sqrt_approx(x):
    # Simple Newton-Raphson
    guess = x / 2
    return guess  # Simplified

def percentage(value, total):
    return value / total * 100  # BUG: No guard for total=0

# Trigger
result = percentage(50, 0)
