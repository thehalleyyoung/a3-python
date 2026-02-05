#!/usr/bin/env python3
"""Debug why index 1 with len_lower_bound=2 reports a bug."""

from pyfromscratch.semantics.bytecode_summaries import analyze_code_object
import dis

def conditional_list(flag):
    if flag:
        return [1, 2, 3, 4, 5]
    else:
        return [1, 2]

def access_index_1():
    x = conditional_list(True)
    return x[1]

print("=== Analyzing conditional_list ===")
cond_summary = analyze_code_object(conditional_list.__code__, func_name='conditional_list')
print(f"Return len: [{cond_summary.return_len_lower_bound}, {cond_summary.return_len_upper_bound}]")
print(f"Return emptiness: {cond_summary.return_emptiness}")

print("\n=== Bytecode for access_index_1 ===")
dis.dis(access_index_1)

print("\n=== Analyzing access_index_1 ===")
idx1_summary = analyze_code_object(
    access_index_1.__code__,
    func_name='access_index_1',
    callee_summaries={'conditional_list': cond_summary}
)

print(f"\nBugs: {len(idx1_summary.potential_bugs)}")
for bug in idx1_summary.potential_bugs:
    print(f"  {bug.bug_type} at offset {bug.offset}: confidence {bug.confidence}, guarded={bug.is_guarded}")
