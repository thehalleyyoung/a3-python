#!/usr/bin/env python3
"""
Quick check: Are verification layers being called at all?
"""
from pathlib import Path
from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer
from pyfromscratch.barriers.extreme_verification import verify_bug_extreme

print("Building call graph...")
deepspeed_path = Path('external_tools/DeepSpeed/deepspeed')
call_graph = build_call_graph_from_directory(deepspeed_path)

print("Computing crash summaries...")
summary_computer = BytecodeCrashSummaryComputer(call_graph)
crash_summaries = summary_computer.compute_all()

print(f"\nFound {len(crash_summaries)} functions")

# Pick first function with bugs
test_func = None
test_summary = None
for func_name, summary in crash_summaries.items():
    if summary.may_trigger:
        test_func = func_name
        test_summary = summary
        break

if not test_func:
    print("No functions with potential bugs found!")
    exit(1)

print(f"\nTesting function: {test_func}")
print(f"Potential bugs: {test_summary.may_trigger}")
print(f"Guarded bugs: {test_summary.guarded_bugs}")

# Test each bug type
for bug_type in test_summary.may_trigger:
    print(f"\n{'='*60}")
    print(f"Testing {bug_type} verification...")
    print(f"{'='*60}")
    
    result = verify_bug_extreme(
        bug_type=bug_type,
        bug_variable=None,
        crash_summary=test_summary,
        call_chain_summaries=[],
        code_object=None,
        source_code=None
    )
    
    print(f"Result: {'SAFE' if result.is_safe else 'UNSAFE'}")
    print(f"Time: {result.verification_time_ms:.2f}ms")
    print(f"Guard barriers: {len(result.guard_barriers)}")
    print(f"Synthesized barriers: {len(result.synthesized_barriers)}")
    
    if result.is_safe:
        print("✓ This bug would be filtered as FP")
    else:
        print("✗ This bug would remain")
    
    # Only test first bug
    break

print("\nDone!")
