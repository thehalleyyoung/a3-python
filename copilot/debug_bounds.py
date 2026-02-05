#!/usr/bin/env python3
"""Test bounds guard detection in crash summary analyzer."""
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryAnalyzer

def test_bounds_check(arr, i):
    if i < len(arr):
        return arr[i]
    return None

def test_no_check(arr, i):
    return arr[i]

def test_range_loop(arr):
    total = 0
    for i in range(len(arr)):
        total += arr[i]
    return total

# Analyze all
safe = BytecodeCrashSummaryAnalyzer(test_bounds_check.__code__, 'test_bounds_check', 'test_bounds_check')
safe.analyze()

unsafe = BytecodeCrashSummaryAnalyzer(test_no_check.__code__, 'test_no_check', 'test_no_check')
unsafe.analyze()

loop = BytecodeCrashSummaryAnalyzer(test_range_loop.__code__, 'test_range_loop', 'test_range_loop')
loop.analyze()

print('=== Safe function (with bounds check) ===')
print(f'BOUNDS guarded: {safe.summary.guard_counts.get("BOUNDS", (0,0))[0]}')
print(f'BOUNDS unguarded: {safe.summary.guard_counts.get("BOUNDS", (0,0))[1]}')
print(f'May raise INDEX_ERROR: {"INDEX_ERROR" in str(safe.summary.may_raise)}')

print('\n=== Unsafe function (no check) ===')
print(f'BOUNDS guarded: {unsafe.summary.guard_counts.get("BOUNDS", (0,0))[0]}')
print(f'BOUNDS unguarded: {unsafe.summary.guard_counts.get("BOUNDS", (0,0))[1]}')
print(f'May raise INDEX_ERROR: {"INDEX_ERROR" in str(unsafe.summary.may_raise)}')

print('\n=== Range loop (range(len(arr))) ===')
print(f'BOUNDS guarded: {loop.summary.guard_counts.get("BOUNDS", (0,0))[0]}')
print(f'BOUNDS unguarded: {loop.summary.guard_counts.get("BOUNDS", (0,0))[1]}')
print(f'May raise INDEX_ERROR: {"INDEX_ERROR" in str(loop.summary.may_raise)}')
