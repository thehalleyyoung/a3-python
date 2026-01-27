"""Standalone test for DIV_ZERO in loop."""

def sum_inverses(n):
    total = 0
    for i in range(n, -1, -1):
        total += 1 / i  # Fails when i = 0
    return total

result = sum_inverses(5)
