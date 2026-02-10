"""
Test to demonstrate the length guard fix.
Run: a3 scan test_length_guards.py --interprocedural
"""

# UNSAFE: No length check
def unsafe_access(data):
    """Should report BOUNDS bug."""
    return data[2]  # BOUNDS: No guard


# SAFE: Length check with >=
def safe_with_gte(data):
    """Should NOT report BOUNDS bug."""
    if len(data) >= 3:
        return data[2]  # SAFE: len(data) >= 3 guards data[2]
    return None


# SAFE: Length check with >
def safe_with_gt(data):
    """Should NOT report BOUNDS bug."""
    if len(data) > 2:
        return data[2]  # SAFE: len(data) > 2 => len(data) >= 3 guards data[2]
    return None


# SAFE: Multiple indices guarded
def safe_multiple_indices(data):
    """Should NOT report BOUNDS bugs."""
    if len(data) >= 5:
        a = data[0]  # SAFE: 0 < 5
        b = data[2]  # SAFE: 2 < 5
        c = data[4]  # SAFE: 4 < 5
        return a + b + c
    return 0


# UNSAFE: Index out of guarded range
def unsafe_outside_guard(data):
    """Should report BOUNDS bug for data[5]."""
    if len(data) >= 3:
        a = data[0]  # SAFE
        b = data[2]  # SAFE
        c = data[5]  # BOUNDS: 5 >= 3, not guarded
        return a + b + c
    return 0


# SAFE: Negative indices
def safe_negative_index(data):
    """Should NOT report BOUNDS bug."""
    if len(data) >= 3:
        return data[-1]  # SAFE: -1 is valid when len >= 3
    return None
