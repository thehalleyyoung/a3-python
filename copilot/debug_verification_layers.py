#!/usr/bin/env python3
"""
Debug why verification layers aren't catching FPs.
"""
import logging
from pathlib import Path
from collections import defaultdict

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.barriers.extreme_verification import ExtremeContextVerifier

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s [%(name)s] %(message)s'
)

# Limit to just a few bugs to see what's happening
MAX_BUGS_TO_DEBUG = 10

print("="*80)
print("DEBUGGING VERIFICATION LAYERS")
print("="*80)

# Build call graph
deepspeed_path = Path('external_tools/DeepSpeed/deepspeed')
print(f"\n[1/4] Building call graph...")
call_graph = build_call_graph_from_directory(deepspeed_path)
print(f"  Functions: {len(call_graph.functions)}")

# Compute crash summaries
print(f"\n[2/4] Computing crash summaries (cached)...")
summary_computer = BytecodeCrashSummaryComputer(call_graph)
crash_summaries = summary_computer.compute_all()
print(f"  Summaries: {len(crash_summaries)}")

# Create tracker
print(f"\n[3/4] Creating bug tracker...")
tracker = InterproceduralBugTracker(
    crash_summaries=crash_summaries,
    call_graph=call_graph,
    entry_points=set(call_graph.functions.keys()),
    reachable_functions=set(call_graph.functions.keys()),
)

# Train Layer 0
print(f"\n[4/4] Training Layer 0 and finding bugs...")
verifier = ExtremeContextVerifier()
if hasattr(verifier, 'fast_filters'):
    verifier.fast_filters.learn_from_codebase(crash_summaries)
    print("  Layer 0 trained!")

# Find all bugs
all_bugs = tracker.find_all_bugs()
print(f"\n  Found {len(all_bugs)} bugs total")

# Group by type
bugs_by_type = defaultdict(list)
for bug in all_bugs:
    bugs_by_type[bug.bug_type].append(bug)

print(f"\nBugs by type:")
for bug_type, bugs in sorted(bugs_by_type.items()):
    print(f"  {bug_type}: {len(bugs)}")

# Now let's manually verify a few bugs and see what each layer says
print("\n" + "="*80)
print("DETAILED VERIFICATION OF SAMPLE BUGS")
print("="*80)

bug_count = 0
for bug_type, bugs in bugs_by_type.items():
    for bug in bugs[:3]:  # Check 3 bugs of each type
        if bug_count >= MAX_BUGS_TO_DEBUG:
            break
        
        bug_count += 1
        func_name = getattr(bug, 'function_name', getattr(bug, 'func_name', 'unknown'))
        bug_var = getattr(bug, 'bug_variable', getattr(bug, 'variable', None))
        
        print(f"\n{'='*80}")
        print(f"BUG #{bug_count}: {bug_type} in {func_name}")
        if bug_var:
            print(f"  Variable: {bug_var}")
        print(f"{'='*80}")
        
        # Get the crash summary for this function
        summary = crash_summaries.get(func_name)
        if not summary:
            print("  ✗ No crash summary found")
            continue
        
        print(f"\n  Crash Summary Info:")
        print(f"    - Guarded bugs: {summary.guarded_bugs}")
        print(f"    - May trigger: {summary.may_trigger}")
        print(f"    - Return guarantees: {summary.return_guarantees}")
        print(f"    - Guard types: {list(summary.guard_type_to_vars.keys())}")
        print(f"    - Bytecode instructions: {len(summary.bytecode_instructions)}")
        
        # Try to verify with extreme verifier
        print(f"\n  Testing verification layers:")
        
        from pyfromscratch.barriers.extreme_verification import verify_bug_extreme
        
        result = verify_bug_extreme(
            bug_type=bug_type,
            bug_variable=bug_var,
            crash_summary=summary,
            call_chain_summaries=[],
            code_object=None,
            source_code=None
        )
        
        print(f"\n  Verification Result:")
        print(f"    - Is safe: {result.is_safe}")
        print(f"    - Guard barriers: {len(result.guard_barriers)}")
        print(f"    - Synthesized barriers: {len(result.synthesized_barriers)}")
        print(f"    - Time: {result.verification_time_ms:.2f}ms")
        
        if result.is_safe:
            print(f"    ✓ VERIFIED SAFE (should be filtered as FP)")
        else:
            print(f"    ✗ NOT VERIFIED (remains as bug)")
    
    if bug_count >= MAX_BUGS_TO_DEBUG:
        break

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"Debugged {bug_count} bugs")
print("\nCheck the DEBUG logs above to see what each layer is doing")
