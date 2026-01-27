"""Standalone test for ASSERT_FAIL - SAFE."""

def check_positive_safe(x):
    if x <= 0:
        return 0
    assert x > 0
    return x * 2

result = check_positive_safe(-5)  # Safe due to early return
