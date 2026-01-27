"""Standalone test for NULL_PTR - optional return."""

def use_found():
    found = None
    return found.upper()  # found is None

result = use_found()
