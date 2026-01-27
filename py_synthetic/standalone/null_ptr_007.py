"""Standalone test for NULL_PTR - regex match."""

def match_and_group():
    m = None
    return m.group(1)  # m is None

result = match_and_group()
