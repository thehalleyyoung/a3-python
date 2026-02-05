#!/usr/bin/env python3
"""
Direct barrier certificate test on numeric code.
Bypasses security scanning to focus on barrier-theory bugs.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.frontend.loader import load_python_file
from pyfromscratch.semantics.symbolic_vm import SymbolicVM
from pyfromscratch.unsafe.registry import check_unsafe_regions
from pyfromscratch.barriers import BarrierSynthesizer, SynthesisConfig


def analyze_for_barriers(code, max_steps=100):
    """Direct barrier analysis without security scanning."""
    vm = SymbolicVM()
    path = vm.load_code(code)
    
    paths_explored = []
    bugs_found = []
    
    # Symbolic execution
    steps = 0
    active = [path]
    
    while active and steps < max_steps:
        current = active.pop(0)
        steps += 1
        
        if current.state.halted:
            paths_explored.append(current)
            continue
        
        # Check for unsafe regions (DIV_ZERO, BOUNDS, etc.)
        unsafe_result = check_unsafe_regions(current.state, [])
        if unsafe_result:
            for bug_type, detail in unsafe_result:
                bugs_found.append((bug_type, detail))
            paths_explored.append(current)
            continue
        
        # Step
        try:
            new_paths = vm.step(current)
            active.extend(new_paths)
        except Exception:
            paths_explored.append(current)
    
    return {
        "bugs": bugs_found,
        "paths_explored": len(paths_explored),
        "steps": steps,
    }


def main():
    # Test on simple numeric code
    test_code = '''
def calculate_ratio(a, b):
    if b > 0:
        return a / b
    return 0.0

def unsafe_divide(x, y):
    # No guard - potential div by zero
    return x / y

result = calculate_ratio(10, 5)
'''
    
    print("Testing barrier analysis on numeric code")
    print("=" * 60)
    
    # Compile the code
    code = compile(test_code, "<test>", "exec")
    
    print(f"\nTest code has {len(code.co_consts)} constants, {len(code.co_names)} names")
    
    result = analyze_for_barriers(code, max_steps=50)
    
    print(f"\nResults:")
    print(f"  Paths explored: {result['paths_explored']}")
    print(f"  Steps taken: {result['steps']}")
    print(f"  Bugs found: {len(result['bugs'])}")
    
    for bug_type, detail in result['bugs']:
        print(f"    [{bug_type}] {detail}")
    
    # Now try Qlib utils
    print("\n" + "=" * 60)
    print("Testing on Qlib utils/time.py")
    
    qlib_file = Path("external_tools/Qlib/qlib/utils/time.py")
    if qlib_file.exists():
        try:
            code = load_python_file(qlib_file)
            result = analyze_for_barriers(code, max_steps=100)
            
            print(f"  Paths explored: {result['paths_explored']}")
            print(f"  Steps taken: {result['steps']}")
            print(f"  Bugs found: {len(result['bugs'])}")
            
            for bug_type, detail in result['bugs'][:5]:
                print(f"    [{bug_type}] {detail}")
        except Exception as e:
            print(f"  Error: {e}")
    else:
        print("  File not found")


if __name__ == "__main__":
    main()
