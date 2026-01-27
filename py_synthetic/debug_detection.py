#!/usr/bin/env python3
"""Debug script to test bug detection types."""

import sys
sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')

from pyfromscratch.analyzer import Analyzer
from pathlib import Path
import tempfile


def test_bounds():
    """Test BOUNDS detection."""
    code = '''
def test():
    items = []
    return items[0]

result = test()
'''
    return run_test("BOUNDS", code)


def test_div_zero():
    """Test DIV_ZERO detection."""
    code = '''
def divide(a, b):
    return a / b

result = divide(10, 0)
'''
    return run_test("DIV_ZERO", code)


def test_null_ptr():
    """Test NULL_PTR detection."""
    code = '''
def get_attr(obj):
    return obj.x

result = get_attr(None)
'''
    return run_test("NULL_PTR", code)


def run_test(expected: str, code: str):
    """Run test and report result."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        path = Path(f.name)
    
    try:
        analyzer = Analyzer(max_paths=100, max_depth=50, verbose=False)
        result = analyzer.analyze_file(path)
        
        detected = result.bug_type if result.verdict == "BUG" else "NONE"
        exception = None
        if result.counterexample:
            exception = result.counterexample.get("final_state", {}).get("exception")
        
        status = "PASS" if detected == expected else "FAIL"
        print(f"{status}: Expected {expected}, got {detected} (exception: {exception})")
        return detected == expected
    finally:
        path.unlink()


if __name__ == "__main__":
    print("Testing bug type detection:")
    print()
    test_bounds()
    test_div_zero()
    test_null_ptr()
