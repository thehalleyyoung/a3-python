"""Standalone test for BOUNDS - large index."""

def get_item_large_index(items, index):
    return items[index]

result = get_item_large_index([1, 2, 3], 100)  # Index too large
