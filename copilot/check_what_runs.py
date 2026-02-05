#!/usr/bin/env python3
"""
Check what actually runs during bug detection.
"""
import logging
import sys
from pathlib import Path

# Suppress warnings
logging.basicConfig(level=logging.ERROR)

sys.path.insert(0, '.')

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

print('='*70)
print('CHECKING WHAT ACTUALLY RUNS')
print('='*70)

print('\n[1/3] Building tracker...')
tracker = InterproceduralBugTracker.from_project(
    Path('external_tools/DeepSpeed'), 
    None
)

print(f'  Functions in codebase: {len(tracker.crash_summaries)}')

print('\n[2/3] Finding bugs...')
bugs = tracker.find_all_bugs(only_non_security=True)

print(f'  Total bugs found: {len(bugs)}')

print('\n[3/3] Analyzing verification coverage...')

# Count functions with guarded bugs
functions_with_guards = 0
total_guarded_bug_types = 0

for func_name, summary in tracker.crash_summaries.items():
    if hasattr(summary, 'guarded_bugs') and summary.guarded_bugs:
        functions_with_guards += 1
        total_guarded_bug_types += len(summary.guarded_bugs)

print(f'  Functions with guards: {functions_with_guards}/{len(tracker.crash_summaries)} ({100*functions_with_guards/len(tracker.crash_summaries):.1f}%)')
print(f'  Total guarded bug types: {total_guarded_bug_types}')

# Check which bugs would actually get extreme verification
would_get_verification = 0
would_skip = 0

for bug in bugs:
    func_name = bug.crash_function
    bug_type = bug.bug_type
    summary = tracker.crash_summaries.get(func_name)
    
    # Check if this matches the condition in _check_direct_bugs
    skip_verification = bug_type in ['VALUE_ERROR', 'RUNTIME_ERROR', 'TYPE_ERROR']
    
    if summary and hasattr(summary, 'guarded_bugs'):
        is_guarded = bug_type in summary.guarded_bugs
        
        if is_guarded and not skip_verification:
            would_get_verification += 1
        else:
            would_skip += 1
    else:
        would_skip += 1

print(f'\n  Bugs that WOULD get 25-paper verification: {would_get_verification}/{len(bugs)} ({100*would_get_verification/len(bugs):.1f}%)')
print(f'  Bugs that SKIP verification: {would_skip}/{len(bugs)} ({100*would_skip/len(bugs):.1f}%)')

print('\n' + '='*70)
print('CONCLUSION:')
print('='*70)
if would_get_verification == 0:
    print('❌ NONE of the bugs get the 25-paper verification!')
    print('   The expensive machinery is never invoked.')
elif would_get_verification < len(bugs) * 0.1:
    print(f'⚠️  Only {would_get_verification} bugs ({100*would_get_verification/len(bugs):.1f}%) get verification.')
    print('   Most bugs skip the expensive layers.')
else:
    print(f'✓ {would_get_verification} bugs ({100*would_get_verification/len(bugs):.1f}%) get full verification.')
    print('  The 25-paper system is actively used.')

# Show sample of what would be verified
print('\nSample bugs that would get verification:')
count = 0
for bug in bugs:
    if count >= 5:
        break
    func_name = bug.crash_function
    bug_type = bug.bug_type
    summary = tracker.crash_summaries.get(func_name)
    
    skip_verification = bug_type in ['VALUE_ERROR', 'RUNTIME_ERROR', 'TYPE_ERROR']
    
    if summary and hasattr(summary, 'guarded_bugs') and bug_type in summary.guarded_bugs and not skip_verification:
        print(f'  - {bug_type} in {func_name}')
        count += 1

if count == 0:
    print('  (none)')
