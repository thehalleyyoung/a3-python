#!/usr/bin/env python3
"""Debug script to see what's happening with interprocedural analysis."""

from pyfromscratch.semantics.bytecode_summaries import BytecodeAbstractInterpreter, analyze_code_object
import dis

def get_list():
    return [1, 2, 3]

def safe_access():
    x = get_list()
    return x[1]

print("=== Analyzing get_list ===")
get_list_summary = analyze_code_object(get_list.__code__, func_name='get_list')
print(f"Return len bounds: [{get_list_summary.return_len_lower_bound}, {get_list_summary.return_len_upper_bound}]")

print("\n=== Bytecode for safe_access ===")
dis.dis(safe_access)

print("\n=== Analyzing safe_access WITH summary ===")
interpreter = BytecodeAbstractInterpreter(
    code=safe_access.__code__,
    func_name='safe_access',
    qualified_name='safe_access',
    callee_summaries={'get_list': get_list_summary}
)

# Monkey patch to add debug
original_handle_call = interpreter._handle_call
def debug_handle_call(state, arg, offset, guards, instr):
    print(f"\n  _handle_call at offset {offset}")
    print(f"  Stack before: {len(state.stack)}")
    result = original_handle_call(state, arg, offset, guards, instr)
    if state.stack:
        top = state.stack[-1]
        print(f"  Result len bounds: [{top.len_lower_bound}, {top.len_upper_bound}]")
        print(f"  Result emptiness: {top.emptiness}")
    return result

interpreter._handle_call = debug_handle_call

summary = interpreter.analyze()
print(f"\nBugs: {len(summary.potential_bugs)}")
for bug in summary.potential_bugs:
    print(f"  {bug.bug_type} at offset {bug.offset}: conf {bug.confidence}")
