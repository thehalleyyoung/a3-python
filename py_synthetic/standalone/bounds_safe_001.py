"""Standalone test for BOUNDS - SAFE version with guard."""

def safe_get(items, index):
    if index < 0 or index >= len(items):
        return None
    return items[index]

result = safe_get([1, 2, 3], 100)  # Safe due to guard
