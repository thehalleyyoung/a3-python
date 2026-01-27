"""Standalone test for BOUNDS - off by one."""

def get_middle(items):
    mid = len(items) // 2
    return items[mid], items[mid + 1]  # mid+1 may be out of bounds

result = get_middle([1])  # mid=0, mid+1=1 is out of bounds
