#!/usr/bin/env python3
"""Test bytecode-level FP reduction improvements."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

print("="*80)
print("TESTING BYTECODE-LEVEL FP REDUCTION")
print("="*80)

# Test 1: Divisor validation detection
print("\n[Test 1] DIV_ZERO with validation")
test_code_1 = """
def safe_division(x, y):
    assert y > 0, "Divisor must be positive"
    return x / y
"""

# Test 2: param_0 (self) NULL_PTR
print("\n[Test 2] NULL_PTR on self")
test_code_2 = """
class MyClass:
    def method(self):
        return self.value  # self is never None
"""

# Test 3: Exception handler
print("\n[Test 3] VALUE_ERROR with handler")
test_code_3 = """
def parse_int(s):
    try:
        return int(s)
    except ValueError:
        return 0  # Expected, not a bug
"""

# Test 4: Expected dunder exception
print("\n[Test 4] __getitem__ KeyError")
test_code_4 = """
class Dict:
    def __getitem__(self, key):
        return self._data[key]  # KeyError is expected
"""

print("\nExpected Results:")
print("  Test 1: DIV_ZERO should be SAFE (validation detected)")
print("  Test 2: NULL_PTR should be SAFE (self never None)")
print("  Test 3: VALUE_ERROR should be SAFE (exception handled)")
print("  Test 4: KEY_ERROR should be SAFE (expected in dunder)")

print("\n" + "="*80)
print("FP Reduction Mechanisms:")
print("="*80)
print("  1. Bytecode validation detection (_has_divisor_validation_bytecode)")
print("  2. Semantic self/cls knowledge (param_0 in methods)")
print("  3. Exception handler detection (_is_caught_exception)")
print("  4. Expected dunder exceptions (Phase 0 filters)")
print("  5. Type annotation analysis (Optional vs non-Optional)")
