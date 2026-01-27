"""Standalone test for ASSERT_FAIL."""

def check_positive(x):
    assert x > 0
    return x * 2

result = check_positive(-5)
