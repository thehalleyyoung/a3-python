#!/usr/bin/env python3
"""Debug script to see what's happening with BUILD_LIST and return values."""

from pyfromscratch.semantics.bytecode_summaries import analyze_code_object
import dis

def get_list():
    return [1, 2, 3]

print("=== Bytecode for get_list ===")
dis.dis(get_list)

print("\n=== Analyzing get_list ===")
summary = analyze_code_object(get_list.__code__, func_name='get_list')

print(f"\nReturn values: {len(summary.return_values)}")
for i, ret_val in enumerate(summary.return_values):
    print(f"  Return {i}:")
    print(f"    emptiness: {ret_val.emptiness}")
    print(f"    len_lower_bound: {ret_val.len_lower_bound}")
    print(f"    len_upper_bound: {ret_val.len_upper_bound}")

print(f"\nSummary:")
print(f"  return_emptiness: {summary.return_emptiness}")
print(f"  return_len_lower_bound: {summary.return_len_lower_bound}")
print(f"  return_len_upper_bound: {summary.return_len_upper_bound}")
