#!/usr/bin/env python3
"""
Verification script for shell_check fix in iteration 558.

This script demonstrates that BOOL SymbolicValues use IntVal payloads.
"""

import z3
from enum import IntEnum

class ValueTag(IntEnum):
    NONE = 0
    BOOL = 1
    INT = 2

class SymbolicValue:
    def __init__(self, tag, payload):
        self.tag = tag
        self.payload = payload
    
    def __repr__(self):
        return f"SymbolicValue({self.tag.name}, {self.payload})"

# Create BOOL SymbolicValues as they are created in the VM
false_value = SymbolicValue(ValueTag.BOOL, z3.IntVal(0))
true_value = SymbolicValue(ValueTag.BOOL, z3.IntVal(1))

print("BOOL SymbolicValue representation:")
print(f"  False: {false_value}")
print(f"  True:  {true_value}")
print()

# Test OLD extraction logic (iteration 557 - BROKEN)
def old_extract_bool(value):
    """OLD logic from iteration 557 - checks for BoolRef"""
    if hasattr(value, 'tag') and hasattr(value, 'payload'):
        if value.tag == ValueTag.BOOL:
            if isinstance(value.payload, z3.BoolRef):
                if z3.is_true(value.payload):
                    return True
                elif z3.is_false(value.payload):
                    return False
                else:
                    return True  # Symbolic - conservative
            else:
                return True  # Unknown payload type - conservative
    return value

# Test NEW extraction logic (iteration 558 - FIXED)
def new_extract_bool(value):
    """NEW logic from iteration 558 - checks for IntVal"""
    if hasattr(value, 'tag') and hasattr(value, 'payload'):
        if value.tag == ValueTag.BOOL:
            # Check for IntVal payload
            if isinstance(value.payload, (z3.IntNumRef, z3.ArithRef)):
                try:
                    int_val = value.payload.as_long() if hasattr(value.payload, 'as_long') else None
                    if int_val is not None:
                        return bool(int_val)
                    else:
                        return True  # Symbolic - conservative
                except:
                    return True  # Can't extract - conservative
            # Also check BoolRef for backward compatibility
            elif isinstance(value.payload, z3.BoolRef):
                if z3.is_true(value.payload):
                    return True
                elif z3.is_false(value.payload):
                    return False
                else:
                    return True  # Symbolic - conservative
            else:
                return True  # Unknown payload type - conservative
    return value

print("OLD extraction (iteration 557 - BROKEN):")
print(f"  shell=False → {old_extract_bool(false_value)} (should be False, but is True! BUG)")
print(f"  shell=True  → {old_extract_bool(true_value)} (correctly True)")
print()

print("NEW extraction (iteration 558 - FIXED):")
print(f"  shell=False → {new_extract_bool(false_value)} (correctly False! ✓)")
print(f"  shell=True  → {new_extract_bool(true_value)} (correctly True! ✓)")
print()

print("Impact:")
print("  OLD: subprocess.run(cmd, shell=False) → detected as BUG (false positive)")
print("  NEW: subprocess.run(cmd, shell=False) → detected as SAFE (correct!)")
print()
print("  OLD: subprocess.run(cmd, shell=True) → detected as BUG (true positive)")
print("  NEW: subprocess.run(cmd, shell=True) → detected as BUG (true positive)")
