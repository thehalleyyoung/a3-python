"""Standalone test for NULL_PTR - pop returns None."""

def use_popped():
    value = None
    return value.strip()  # value is None

result = use_popped()
