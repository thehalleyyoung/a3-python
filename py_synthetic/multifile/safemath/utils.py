"""Safe math - all operations have guards - SAFE."""

def safe_divide(a, b):
    if b == 0:
        return 0
    return a / b

def safe_average(items):
    if len(items) == 0:
        return 0
    return sum(items) / len(items)

# Test with zero - should be safe
result1 = safe_divide(10, 0)
result2 = safe_average([])
