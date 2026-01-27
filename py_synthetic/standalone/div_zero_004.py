"""Standalone test for DIV_ZERO - average calculation."""

def calculate_average(items):
    total = sum(items)
    return total / len(items)

result = calculate_average([])  # Empty list = div by 0
