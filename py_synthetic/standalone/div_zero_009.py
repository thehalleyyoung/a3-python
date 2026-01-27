"""Standalone test for DIV_ZERO - conditional path."""

def conditional_div(x, y):
    if x > 0:
        return x / y  # y could be 0
    return 0

result = conditional_div(10, 0)
