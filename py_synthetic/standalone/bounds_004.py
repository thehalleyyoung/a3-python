"""Standalone test for BOUNDS - access past end."""

def parse_pair():
    parts = ["a"]  # Only 1 element
    return (parts[0], parts[1])  # parts[1] fails

result = parse_pair()
