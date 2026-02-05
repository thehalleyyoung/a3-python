#!/usr/bin/env python3
"""
Find specific bug patterns where deep verification (Papers #1-20) should help
but cheap phases don't catch them.

Target scenarios:
1. Loop invariants - needs Papers #9-12 (ICE learning)
2. Complex aliasing - needs Papers #5-8 (CEGAR)  
3. Numeric constraints - needs Papers #13-16 (IC3)
4. Recursive functions - needs Papers #17-20 (CHC solving)
"""
import sys
from pathlib import Path
import pickle
from collections import defaultdict

# Load summaries
cache_file = Path('results/deepspeed_crash_summaries.pkl')
if not cache_file.exists():
    print(f"ERROR: {cache_file} not found")
    sys.exit(1)

print("Loading summaries...")
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)
print(f"Loaded {len(summaries)} summaries\n")

# Scenarios where deep verification should help
scenarios = {
    'loop_invariants': [],
    'array_bounds_with_iteration': [],
    'division_by_computed_value': [],
    'recursive_null_check': [],
    'aliasing_issues': [],
}

print("="*80)
print("ANALYZING BUGS FOR DEEP VERIFICATION OPPORTUNITIES")
print("="*80)
print()

for func_name, summary in summaries.items():
    # Scenario 1: Loop invariants (ICE learning - Papers #9-12)
    # Pattern: Division or indexing where divisor/index comes from loop iteration
    if hasattr(summary, 'instructions'):
        has_loop = any('FOR_ITER' in str(instr.opname) for instr in summary.instructions)
        has_div = any('BINARY_OP' in str(instr.opname) for instr in summary.instructions)
        has_subscr = any('BINARY_SUBSCR' in str(instr.opname) for instr in summary.instructions)
        
        if has_loop and (has_div or has_subscr):
            scenarios['loop_invariants'].append({
                'function': func_name,
                'reason': 'Loop with division/indexing - needs invariant learning',
                'paper_group': 'Papers #9-12 (ICE)',
                'bug_types': ['DIV_ZERO', 'BOUNDS']
            })
    
    # Scenario 2: Array bounds with computed indices
    # Pattern: list[expr] where expr is computed (not constant)
    if hasattr(summary, 'may_trigger'):
        if 'BOUNDS' in summary.may_trigger:
            # Check if index is computed
            if hasattr(summary, 'instructions'):
                has_math_ops = any(
                    op in str(instr.opname) 
                    for instr in summary.instructions
                    for op in ['BINARY_ADD', 'BINARY_SUBTRACT', 'BINARY_MULTIPLY']
                )
                if has_math_ops:
                    scenarios['array_bounds_with_iteration'].append({
                        'function': func_name,
                        'reason': 'Array indexing with computed index - needs range analysis',
                        'paper_group': 'Papers #13-16 (IC3)',
                        'bug_types': ['BOUNDS']
                    })
    
    # Scenario 3: Division by expression (not just variable)
    # Pattern: x / (a + b) or x / max(y, 1) - needs constraint solving
    if hasattr(summary, 'may_trigger'):
        if 'DIV_ZERO' in summary.may_trigger:
            if hasattr(summary, 'instructions'):
                # Look for division after arithmetic
                has_div_after_math = False
                last_was_math = False
                for instr in summary.instructions:
                    if 'BINARY_OP' in str(instr.opname) or 'BINARY_MULTIPLY' in str(instr.opname):
                        last_was_math = True
                    elif 'BINARY_TRUE_DIVIDE' in str(instr.opname) or 'BINARY_FLOOR_DIVIDE' in str(instr.opname):
                        if last_was_math:
                            has_div_after_math = True
                        last_was_math = False
                    else:
                        last_was_math = False
                
                if has_div_after_math:
                    scenarios['division_by_computed_value'].append({
                        'function': func_name,
                        'reason': 'Division by computed expression - needs constraint solving',
                        'paper_group': 'Papers #13-16 (IC3/PDR)',
                        'bug_types': ['DIV_ZERO']
                    })
    
    # Scenario 4: Recursive functions with null checks
    # Pattern: Recursive call with pointer parameters - needs CHC solving
    if hasattr(summary, 'instructions'):
        has_recursive_call = False
        func_short_name = func_name.split('.')[-1] if '.' in func_name else func_name
        
        for instr in summary.instructions:
            if 'CALL' in str(instr.opname) and hasattr(instr, 'argval'):
                if func_short_name in str(instr.argval):
                    has_recursive_call = True
                    break
        
        if has_recursive_call and hasattr(summary, 'may_trigger'):
            if 'NULL_PTR' in summary.may_trigger:
                scenarios['recursive_null_check'].append({
                    'function': func_name,
                    'reason': 'Recursive function with null pointer - needs CHC solving',
                    'paper_group': 'Papers #17-20 (CHC)',
                    'bug_types': ['NULL_PTR']
                })
    
    # Scenario 5: Aliasing - multiple names for same object
    # Pattern: param passed to multiple variables, modified, then used
    if hasattr(summary, 'instructions'):
        has_store = any('STORE' in str(instr.opname) for instr in summary.instructions)
        has_load = any('LOAD' in str(instr.opname) for instr in summary.instructions)
        has_null_check = hasattr(summary, 'may_trigger') and 'NULL_PTR' in summary.may_trigger
        
        if has_store and has_load and has_null_check:
            # Rough heuristic: if multiple stores and loads, might have aliasing
            store_count = sum(1 for instr in summary.instructions if 'STORE' in str(instr.opname))
            load_count = sum(1 for instr in summary.instructions if 'LOAD' in str(instr.opname))
            
            if store_count >= 3 and load_count >= 3:
                scenarios['aliasing_issues'].append({
                    'function': func_name,
                    'reason': 'Multiple stores/loads with null check - may need alias analysis',
                    'paper_group': 'Papers #5-8 (CEGAR)',
                    'bug_types': ['NULL_PTR']
                })

# Report findings
print("SCENARIOS WHERE DEEP VERIFICATION SHOULD HELP:")
print("="*80)
print()

total_opportunities = 0
for scenario_name, cases in scenarios.items():
    if cases:
        total_opportunities += len(cases)
        print(f"{scenario_name.upper().replace('_', ' ')}:")
        print(f"  Found {len(cases)} cases")
        
        if cases:
            example = cases[0]
            print(f"  Paper group: {example['paper_group']}")
            print(f"  Bug types: {', '.join(example['bug_types'])}")
            print(f"  Example: {example['function']}")
            print(f"    → {example['reason']}")
        
        print()

print(f"Total deep verification opportunities: {total_opportunities}")
print()

# Create test cases for each scenario
print("="*80)
print("RECOMMENDATIONS")
print("="*80)
print()

if scenarios['loop_invariants']:
    print("1. LOOP INVARIANTS (Papers #9-12 - ICE Learning):")
    print("   - Add loop invariant inference to detect safe iteration bounds")
    print("   - Example: for i in range(n): arr[i] → learn 0 <= i < n")
    print(f"   - {len(scenarios['loop_invariants'])} cases would benefit")
    print()

if scenarios['division_by_computed_value']:
    print("2. CONSTRAINT SOLVING (Papers #13-16 - IC3/PDR):")
    print("   - Add constraint solver to prove divisor != 0")
    print("   - Example: x / max(y, 1) → prove max(y,1) >= 1")
    print(f"   - {len(scenarios['division_by_computed_value'])} cases would benefit")
    print()

if scenarios['array_bounds_with_iteration']:
    print("3. RANGE ANALYSIS (Papers #24 - Interval Analysis in Layer 0):")
    print("   - Strengthen interval analysis to track computed indices")
    print("   - Example: arr[i+offset] → prove 0 <= i+offset < len(arr)")
    print(f"   - {len(scenarios['array_bounds_with_iteration'])} cases would benefit")
    print()

if scenarios['recursive_null_check']:
    print("4. RECURSIVE VERIFICATION (Papers #17-20 - CHC Solving):")
    print("   - Add Horn clause solving for recursive functions")
    print("   - Example: def f(x): if x: f(x.next) → prove termination + null safety")
    print(f"   - {len(scenarios['recursive_null_check'])} cases would benefit")
    print()

if scenarios['aliasing_issues']:
    print("5. ALIAS ANALYSIS (Papers #5-8 - CEGAR):")
    print("   - Add points-to analysis to track object identity")
    print("   - Example: y = x; x = None; use(y) → prove y still valid")
    print(f"   - {len(scenarios['aliasing_issues'])} cases would benefit")
    print()

print("="*80)
print("NEXT STEPS")
print("="*80)
print()
print("1. Fix Bayesian scorer to be more conservative:")
print("   - Don't mark as FP based on 'has_guard' alone")
print("   - Require 2+ independent signals for high confidence")
print("   - Check that guard actually protects THIS specific bug")
print()
print("2. Implement targeted deep verification:")
print(f"   - Focus on {total_opportunities} high-value cases")
print("   - Start with most common scenario")
print("   - Measure FP reduction per paper group")
print()
print("3. Create ground truth for validation:")
print("   - Manually inspect sample from each scenario")
print("   - Verify that deep verification catches real FPs")
print("   - Ensure we're not creating false negatives")
