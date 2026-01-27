"""Standalone test for NULL_PTR - attribute access on None."""

def get_attr(obj):
    return obj.x

result = get_attr(None)  # None has no attribute x
