"""Standalone test for NULL_PTR - SAFE version with guard."""

def safe_get_attr(obj):
    if obj is None:
        return None
    return obj.x

class Obj:
    x = 10

result = safe_get_attr(None)  # Safe due to guard
