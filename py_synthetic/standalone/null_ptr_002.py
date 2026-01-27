"""Standalone test for NULL_PTR - method call on None."""

def call_method(obj):
    return obj.strip()

result = call_method(None)  # Can't call strip on None
