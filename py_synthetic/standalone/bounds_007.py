"""Standalone test for BOUNDS - head and tail."""

def head_tail(items):
    head = items[0]
    tail = items[1:]
    return head, tail

result = head_tail([])
