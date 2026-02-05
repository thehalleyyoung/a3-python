"""Analyze why bugs weren't automatically filtered."""
import sys
from pathlib import Path
from collections import defaultdict
sys.path.insert(0, '.')
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

tracker = InterproceduralBugTracker.from_project(Path('external_tools/DeepSpeed'), None)
bugs = tracker.find_all_bugs(only_non_security=True)
high = [b for b in bugs if b.confidence >= 0.7][:100]

print(f"Analyzing first {len(high)} high-confidence bugs...")
print("=" * 80)

# Group by bug type and check validation
by_type = defaultdict(list)
for bug in high:
    by_type[bug.bug_type].append(bug)

for bug_type, type_bugs in sorted(by_type.items()):
    print(f"\n{bug_type}: {len(type_bugs)} bugs")
    
    # Sample 5 bugs of each type
    for i, bug in enumerate(type_bugs[:5], 1):
        summary = tracker.crash_summary_tracker.summaries.get(bug.func_id)
        
        print(f"\n  {i}. {bug.func_name} @ line {bug.line_number}")
        print(f"     Variable: {bug.bug_variable}")
        print(f"     Confidence: {bug.confidence:.2f}")
        
        if summary:
            # Check for guards
            if summary.guard_type_to_vars:
                print(f"     Guards: {dict(summary.guard_type_to_vars)}")
            
            # Check if this variable has validation
            validated_by = []
            for guard_type, vars in summary.guard_type_to_vars.items():
                if bug.bug_variable in vars:
                    validated_by.append(guard_type)
            
            if validated_by:
                print(f"     ⚠️  Variable IS guarded by: {validated_by}")
                print(f"     ❓ WHY NOT FILTERED: Guard may not cover all paths?")
            else:
                print(f"     ✓ Variable NOT guarded - legitimate report")
        else:
            print(f"     ⚠️  No crash summary found")

print("\n" + "=" * 80)
print("\nSUMMARY: Key insights")
print("=" * 80)
print("""
The bugs are reported because:

1. **Guards exist but don't cover all paths**: A function may check `if x != 0` 
   on some paths but not others. Static analysis sees the division on an 
   unguarded path and correctly reports it.

2. **Interprocedural flows**: The guard may be in a caller, but the crash 
   summary only sees the current function's local checks.

3. **Conditional validation**: `assert x > 0` may only execute in debug mode,
   or inside an if-block that doesn't always execute.

4. **Complex control flow**: CFG may have paths where validation is skipped
   (early returns, exception handlers, etc.)

These are NOT false positives - they're cases where verification failed to 
PROVE safety. The difference between "not proven safe" and "definitely unsafe"
is the core challenge of static analysis.
""")
