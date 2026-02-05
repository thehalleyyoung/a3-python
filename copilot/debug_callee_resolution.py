#!/usr/bin/env python3
"""Debug to see what's happening in analyze_code_object."""

from pyfromscratch.semantics.bytecode_summaries import analyze_code_object
import dis

def get_list():
    return [1, 2, 3]

def safe_access():
    x = get_list()
    return x[1]

print("=== Step 1: Analyze get_list ===")
get_list_summary = analyze_code_object(get_list.__code__, func_name='get_list')
print(f"Return len bounds: [{get_list_summary.return_len_lower_bound}, {get_list_summary.return_len_upper_bound}]")

print("\n=== Step 2: Check callee_summaries dict ===")
callee_summaries = {'get_list': get_list_summary}
print(f"Keys in callee_summaries: {list(callee_summaries.keys())}")
print(f"'get_list' in callee_summaries: {'get_list' in callee_summaries}")

print("\n=== Step 3: Analyze safe_access ===")
print("Bytecode:")
dis.dis(safe_access)

safe_summary = analyze_code_object(
    safe_access.__code__,
    func_name='safe_access',
    callee_summaries=callee_summaries
)

print(f"\nBugs found: {len(safe_summary.potential_bugs)}")
for bug in safe_summary.potential_bugs:
    print(f"  {bug.bug_type} at offset {bug.offset}: conf {bug.confidence}")
