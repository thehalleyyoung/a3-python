"""Standalone test for NULL_PTR - list find."""

def first_or_none(items, predicate):
    for item in items:
        if predicate(item):
            return item
    return None

def use_first(items):
    first = first_or_none(items, lambda x: x > 10)
    return first + 1  # first could be None

result = use_first([1, 2, 3])
