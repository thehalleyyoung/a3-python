"""User DB - query module with bounds bug."""

def get_first():
    users = []  # Empty list
    return users[0]  # BUG: No check for empty

# Trigger
result = get_first()
