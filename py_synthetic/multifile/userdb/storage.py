"""User DB - storage module with bounds bug."""

def get_user(index):
    users = ["Alice", "Bob", "Charlie"]  # 3 elements
    return users[index]  # BUG: No bounds check

# Trigger the bug - index 100 is out of bounds for list of 3
result = get_user(100)
