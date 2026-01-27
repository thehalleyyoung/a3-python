"""Standalone test for NULL_PTR - chained access."""

def nested_get():
    x = None
    return x.upper()  # None has no upper

result = nested_get()
