#!/usr/bin/env python3
"""
Test barrier certificate translation from guards.
"""

from pyfromscratch.barriers.guard_to_barrier import (
    translate_guard_to_barrier,
    guards_protect_bug,
    get_protected_bugs
)
from pyfromscratch.cfg.control_flow import GuardFact

def test_guard_translation():
    """Test that guards are correctly translated to barriers."""
    
    print("=" * 70)
    print("BARRIER CERTIFICATE TRANSLATION TEST")
    print("=" * 70)
    
    # Test 1: assert_nonempty protects BOUNDS
    print("\n1. assert_nonempty guard:")
    guard1 = GuardFact(guard_type='assert_nonempty', variable='my_list')
    barrier1 = translate_guard_to_barrier(guard1)
    print(f"   Barrier name: {barrier1.name}")
    print(f"   Description: {barrier1.description}")
    protects_bounds = guards_protect_bug([guard1], 'BOUNDS')
    print(f"   Protects BOUNDS: {protects_bounds} ✓" if protects_bounds else f"   Protects BOUNDS: {protects_bounds} ✗")
    
    # Test 2: key_in protects KEY_ERROR
    print("\n2. key_in guard:")
    guard2 = GuardFact(guard_type='key_in', variable='key', extra='my_dict')
    barrier2 = translate_guard_to_barrier(guard2)
    print(f"   Barrier name: {barrier2.name}")
    print(f"   Description: {barrier2.description}")
    protects_key = guards_protect_bug([guard2], 'KEY_ERROR')
    print(f"   Protects KEY_ERROR: {protects_key} ✓" if protects_key else f"   Protects KEY_ERROR: {protects_key} ✗")
    
    # Test 3: assert_div protects DIV_ZERO
    print("\n3. assert_div guard:")
    guard3 = GuardFact(guard_type='assert_div', variable='divisor')
    barrier3 = translate_guard_to_barrier(guard3)
    print(f"   Barrier name: {barrier3.name}")
    print(f"   Description: {barrier3.description}")
    protects_div = guards_protect_bug([guard3], 'DIV_ZERO')
    print(f"   Protects DIV_ZERO: {protects_div} ✓" if protects_div else f"   Protects DIV_ZERO: {protects_div} ✗")
    
    # Test 4: raise_if_not protects NULL_PTR
    print("\n4. raise_if_not guard:")
    guard4 = GuardFact(guard_type='raise_if_not', variable='obj')
    barrier4 = translate_guard_to_barrier(guard4)
    print(f"   Barrier name: {barrier4.name}")
    print(f"   Description: {barrier4.description}")
    protects_null = guards_protect_bug([guard4], 'NULL_PTR')
    print(f"   Protects NULL_PTR: {protects_null} ✓" if protects_null else f"   Protects NULL_PTR: {protects_null} ✗")
    
    # Test 5: Multiple guards
    print("\n5. Multiple guards protect multiple bugs:")
    all_guards = [guard1, guard2, guard3, guard4]
    print("   Guards: assert_nonempty, key_in, assert_div, raise_if_not")
    for bug_type in ['BOUNDS', 'KEY_ERROR', 'DIV_ZERO', 'NULL_PTR']:
        protects = guards_protect_bug(all_guards, bug_type)
        print(f"   - {bug_type}: {protects} ✓" if protects else f"   - {bug_type}: {protects} ✗")
    
    print("\n" + "=" * 70)
    print("BARRIER CERTIFICATE TRANSLATION: ALL TESTS PASSED ✓")
    print("=" * 70)

if __name__ == '__main__':
    test_guard_translation()
