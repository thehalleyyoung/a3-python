#!/usr/bin/env python3
"""
Debug: What is Phase -2 catching and why aren't other layers running?
"""
import logging
from pathlib import Path
from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.barriers.extreme_verification import verify_bug_extreme

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

subset_path = Path('external_tools/DeepSpeed/deepspeed/inference')
call_graph = build_call_graph_from_directory(subset_path)
summary_computer = BytecodeCrashSummaryComputer(call_graph)
crash_summaries = summary_computer.compute_all()

# Get one bug to debug
tracker = InterproceduralBugTracker(
    crash_summaries=crash_summaries,
    call_graph=call_graph,
    entry_points=set(call_graph.functions.keys()),
    reachable_functions=set(call_graph.functions.keys()),
)

# Temporarily disable Phase -2 to see if other layers work
print("\n" + "="*80)
print("Testing ONE bug through verification layers")
print("="*80)

# Find first function with bugs
test_summary = None
for func_name, summary in crash_summaries.items():
    if summary.may_trigger:
        test_summary = summary
        bug_type = next(iter(summary.may_trigger))
        print(f"\nTest function: {func_name}")
        print(f"Bug type: {bug_type}")
        break

if test_summary:
    # Manually call verification with debug output
    result = verify_bug_extreme(
        bug_type=bug_type,
        bug_variable='var',
        crash_summary=test_summary,
        call_chain_summaries=[],
        code_object=None,
        source_code=None
    )
    
    print(f"\n{'='*80}")
    print("RESULT:")
    print(f"  is_safe: {result.is_safe}")
    print(f"  guard_barriers: {len(result.guard_barriers)}")
    print(f"  synthesized_barriers: {len(result.synthesized_barriers)}")
    print(f"  time: {result.verification_time_ms:.2f}ms")
