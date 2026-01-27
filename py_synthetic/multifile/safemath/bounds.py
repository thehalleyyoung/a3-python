"""Safe math - bounds operations with guards - SAFE."""

def safe_get(items, index):
    if index < 0 or index >= len(items):
        return None
    return items[index]

def safe_first(items):
    if len(items) == 0:
        return None
    return items[0]

# Test with edge cases - should be safe
result1 = safe_get([1,2,3], 100)
result2 = safe_first([])
