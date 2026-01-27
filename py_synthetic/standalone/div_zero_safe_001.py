"""Standalone test for DIV_ZERO - SAFE version with guard."""

def safe_divide(a, b):
    if b == 0:
        return 0
    return a / b

result = safe_divide(10, 0)  # Safe due to guard
