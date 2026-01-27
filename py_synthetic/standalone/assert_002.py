"""Standalone test for ASSERT_FAIL - precondition."""

def sqrt_approx(x):
    assert x >= 0, "Cannot take sqrt of negative"
    return x ** 0.5

result = sqrt_approx(-1)
