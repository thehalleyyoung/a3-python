"""Standalone test for NULL_PTR - direct None access."""

def get_and_use():
    value = None
    return value.upper()  # None has no upper()

result = get_and_use()
