#!/usr/bin/env python3
"""Test interprocedural bounds checking."""

from pyfromscratch.semantics.bytecode_summaries import analyze_code_object
import dis

def test_interprocedural_list_length():
    """Test that length bounds propagate through function calls."""
    
    # Helper function that returns a list of known length
    def get_list():
        return [1, 2, 3]
    
    # Caller that accesses the list
    def safe_access():
        x = get_list()
        return x[1]  # Should be SAFE: list has length 3
    
    def unsafe_access():
        x = get_list()
        return x[5]  # Should be HIGH CONF BUG: index > length
    
    print("=== Building summary for get_list ===")
    get_list_summary = analyze_code_object(get_list.__code__, func_name='get_list')
    print(f"Return emptiness: {get_list_summary.return_emptiness}")
    print(f"Return len_lower_bound: {get_list_summary.return_len_lower_bound}")
    print(f"Return len_upper_bound: {get_list_summary.return_len_upper_bound}")
    print(f"Bugs in get_list: {len(get_list_summary.potential_bugs)}")
    
    print("\n=== Bytecode for safe_access ===")
    import dis
    dis.dis(safe_access)
    
    print("\n=== Analyzing safe_access with get_list summary ===")
    safe_summary = analyze_code_object(
        safe_access.__code__,
        func_name='safe_access',
        callee_summaries={'get_list': get_list_summary}
    )
    safe_bugs = safe_summary.potential_bugs
    print(f"Bugs in safe_access: {len(safe_bugs)}")
    for bug in safe_bugs:
        print(f"  {bug.bug_type} at offset {bug.offset}: confidence {bug.confidence}")
    
    print("\n=== Analyzing unsafe_access with get_list summary ===")
    unsafe_summary = analyze_code_object(
        unsafe_access.__code__,
        func_name='unsafe_access',
        callee_summaries={'get_list': get_list_summary}
    )
    unsafe_bugs = unsafe_summary.potential_bugs
    print(f"Bugs in unsafe_access: {len(unsafe_bugs)}")
    for bug in unsafe_bugs:
        print(f"  {bug.bug_type} at offset {bug.offset}: confidence {bug.confidence}")
    
    # Assertions
    assert len(safe_bugs) == 0, "safe_access should have 0 bugs"
    assert any(
        bug.bug_type == 'BOUNDS' and bug.confidence >= 0.9
        for bug in unsafe_bugs
    ), "unsafe_access should have high-confidence BOUNDS bug"
    
    print("\n✅ Interprocedural bounds checking PASSED!")

def test_interprocedural_empty_list():
    """Test that emptiness propagates through function calls."""
    
    def get_empty():
        return []
    
    def access_empty():
        x = get_empty()
        return x[0]  # Should be HIGH CONF BUG: list is empty
    
    print("\n=== Building summary for get_empty ===")
    get_empty_summary = analyze_code_object(get_empty.__code__, func_name='get_empty')
    print(f"Return emptiness: {get_empty_summary.return_emptiness}")
    print(f"Return len_lower_bound: {get_empty_summary.return_len_lower_bound}")
    print(f"Return len_upper_bound: {get_empty_summary.return_len_upper_bound}")
    
    print("\n=== Analyzing access_empty ===")
    summary = analyze_code_object(
        access_empty.__code__,
        func_name='access_empty',
        callee_summaries={'get_empty': get_empty_summary}
    )
    bugs = summary.potential_bugs
    print(f"Bugs: {len(bugs)}")
    for bug in bugs:
        print(f"  {bug.bug_type} at offset {bug.offset}: confidence {bug.confidence}")
    
    assert any(
        bug.bug_type == 'BOUNDS' and bug.confidence >= 0.9
        for bug in bugs
    ), "Should detect high-confidence BOUNDS bug on empty list"
    
    print("\n✅ Empty list interprocedural check PASSED!")

def test_interprocedural_guarded():
    """Test that guards work with interprocedural analysis."""
    
    def get_maybe_list(flag):
        if flag:
            return [1, 2, 3]
        return []
    
    def guarded_access():
        x = get_maybe_list(True)
        if len(x) > 2:
            return x[1]  # Should be SAFE: guarded by len check
        return 0
    
    print("\n=== Building summary for get_maybe_list ===")
    get_maybe_summary = analyze_code_object(get_maybe_list.__code__, func_name='get_maybe_list')
    print(f"Return emptiness: {get_maybe_summary.return_emptiness}")
    print(f"Return len_lower_bound: {get_maybe_summary.return_len_lower_bound}")
    print(f"Return len_upper_bound: {get_maybe_summary.return_len_upper_bound}")
    
    print("\n=== Analyzing guarded_access ===")
    summary = analyze_code_object(
        guarded_access.__code__,
        func_name='guarded_access',
        callee_summaries={'get_maybe_list': get_maybe_summary}
    )
    bugs = summary.potential_bugs
    print(f"Bugs: {len(bugs)}")
    for bug in bugs:
        print(f"  {bug.bug_type} at offset {bug.offset}: confidence {bug.confidence}")
    
    # Should have no high-confidence bugs since access is guarded
    high_conf_bugs = [b for b in bugs if b.confidence >= 0.8]
    assert len(high_conf_bugs) == 0, "Guarded access should have no high-confidence bugs"
    
    print("\n✅ Guarded interprocedural check PASSED!")

if __name__ == '__main__':
    test_interprocedural_list_length()
    test_interprocedural_empty_list()
    test_interprocedural_guarded()
    print("\n🎉 All interprocedural bounds tests PASSED!")
