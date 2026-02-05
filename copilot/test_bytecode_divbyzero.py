#!/usr/bin/env python3
"""Direct test of bytecode analyzer on the DeepSpeed pattern."""

from pyfromscratch.semantics.bytecode_summaries import analyze_code_object

def test_div_by_len_pattern():
    """Test the exact pattern from DeepSpeed."""
    
    def merge_slices(slices):
        """This mimics the DeepSpeed pattern."""
        param = sum(slices) / len(slices)
        return param
    
    def merge_with_check(slices):
        """Safe version with guard."""
        if len(slices) > 0:
            param = sum(slices) / len(slices)
            return param
        return 0
    
    def merge_with_elif(slices, should_average):
        """Pattern matching the DeepSpeed code structure."""
        if should_average:
            param = sum(slices) / len(slices)
            return param
        return slices[0]
    
    print("=" * 80)
    print("TESTING DIV_BY_LEN PATTERN WITH BYTECODE ANALYZER")
    print("=" * 80)
    
    # Test 1: Unguarded division
    print("\n1. Unguarded sum(slices) / len(slices)")
    print("-" * 80)
    summary1 = analyze_code_object(merge_slices.__code__, func_name='merge_slices')
    div_bugs1 = [b for b in summary1.potential_bugs if b.bug_type == 'DIV_ZERO']
    print(f"DIV_ZERO bugs: {len(div_bugs1)}")
    for bug in div_bugs1:
        print(f"  Line offset {bug.offset}: confidence {bug.confidence}")
    
    if div_bugs1:
        print("✅ DETECTED: Our analyzer found the potential division by zero!")
    else:
        print("❌ NOT DETECTED: Analyzer missed this bug")
    
    # Test 2: Guarded division
    print("\n2. Guarded sum(slices) / len(slices)")
    print("-" * 80)
    summary2 = analyze_code_object(merge_with_check.__code__, func_name='merge_with_check')
    div_bugs2 = [b for b in summary2.potential_bugs if b.bug_type == 'DIV_ZERO']
    print(f"DIV_ZERO bugs: {len(div_bugs2)}")
    for bug in div_bugs2:
        print(f"  Line offset {bug.offset}: confidence {bug.confidence}, guarded: {bug.is_guarded}")
    
    if not div_bugs2 or all(b.is_guarded for b in div_bugs2):
        print("✅ CORRECT: Guard properly detected!")
    else:
        print("⚠️  Guarded but still reported (conservative analysis)")
    
    # Test 3: DeepSpeed-style elif pattern
    print("\n3. DeepSpeed-style elif pattern")
    print("-" * 80)
    summary3 = analyze_code_object(merge_with_elif.__code__, func_name='merge_with_elif')
    div_bugs3 = [b for b in summary3.potential_bugs if b.bug_type == 'DIV_ZERO']
    bounds_bugs3 = [b for b in summary3.potential_bugs if b.bug_type == 'BOUNDS']
    print(f"DIV_ZERO bugs: {len(div_bugs3)}")
    print(f"BOUNDS bugs: {len(bounds_bugs3)}")
    for bug in div_bugs3:
        print(f"  DIV_ZERO at offset {bug.offset}: confidence {bug.confidence}")
    for bug in bounds_bugs3:
        print(f"  BOUNDS at offset {bug.offset}: confidence {bug.confidence}")
    
    if div_bugs3 or bounds_bugs3:
        print("✅ DETECTED: Potential bugs in conditional branch!")
    else:
        print("❌ NOT DETECTED")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Unguarded pattern: {len(div_bugs1)} bugs")
    print(f"Guarded pattern: {len([b for b in div_bugs2 if not b.is_guarded])} unguarded bugs")
    print(f"Elif pattern: {len(div_bugs3) + len(bounds_bugs3)} bugs")
    
    # Test with interprocedural analysis
    print("\n" + "=" * 80)
    print("INTERPROCEDURAL TEST")
    print("=" * 80)
    
    def get_slices():
        """Might return empty list."""
        return []  # Or could return [1, 2, 3]
    
    def process_slices():
        """Calls get_slices and divides."""
        slices = get_slices()
        return sum(slices) / len(slices)
    
    print("\n4. Interprocedural: get_slices() returns empty list")
    print("-" * 80)
    
    get_slices_summary = analyze_code_object(get_slices.__code__, func_name='get_slices')
    print(f"get_slices return emptiness: {get_slices_summary.return_emptiness}")
    print(f"get_slices return len bounds: [{get_slices_summary.return_len_lower_bound}, {get_slices_summary.return_len_upper_bound}]")
    
    process_summary = analyze_code_object(
        process_slices.__code__,
        func_name='process_slices',
        callee_summaries={'get_slices': get_slices_summary}
    )
    
    div_bugs4 = [b for b in process_summary.potential_bugs if b.bug_type == 'DIV_ZERO']
    print(f"\nDIV_ZERO bugs in process_slices: {len(div_bugs4)}")
    for bug in div_bugs4:
        print(f"  Line offset {bug.offset}: confidence {bug.confidence}")
    
    if div_bugs4:
        print("✅ INTERPROCEDURAL ANALYSIS WORKING!")
        print("   Detected that get_slices() returns empty list → len() = 0 → DIV_ZERO")
    else:
        print("❌ Interprocedural analysis didn't propagate emptiness")


if __name__ == '__main__':
    test_div_by_len_pattern()
