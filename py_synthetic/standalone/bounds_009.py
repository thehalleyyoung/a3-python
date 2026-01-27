"""Standalone test for BOUNDS - tuple unpacking."""

def get_coords():
    parts = ["123"]  # Only 1 element
    x = parts[0]
    y = parts[1]  # Index out of bounds
    return x, y

result = get_coords()
