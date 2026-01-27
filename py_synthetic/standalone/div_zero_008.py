"""Standalone test for DIV_ZERO - nested."""

def nested_div(a, b, c):
    return a / (b - c)

result = nested_div(10, 5, 5)  # b - c = 0
