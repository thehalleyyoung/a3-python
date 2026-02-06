#!/usr/bin/env python3
"""
Analyze the 377 remaining bugs to find patterns where deeper verification
(Papers #1-20) could help reduce FPs.
"""
import sys
from pathlib import Path
import pickle
from collections import defaultdict, Counter

# Load summaries
cache_file = Path('results/deepspeed_crash_summaries.pkl')
if not cache_file.exists():
    print(f"ERROR: {cache_file} not found")
    sys.exit(1)

print("Loading summaries...")
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)
print(f"Loaded {len(summaries)} summaries\n")

# Analyze patterns that could benefit from deep verification
patterns = {
    # Papers #1-4: SOS Semantics
    'exception_caught': [],  # Exception raised but caught → FP
    'validated_in_caller': [],  # Validation in caller, not callee
    
    # Papers #5-8: CEGAR (Counterexample-Guided Abstraction Refinement)
    'guarded_by_earlier_check': [],  # Guard earlier in function protects this
    'type_narrowed_by_isinstance': [],  # isinstance() narrows type → safe
    
    # Papers #9-12: ICE Learning (Learning Invariants from Examples)
    'common_idiom_pattern': [],  # Common safe patterns (len(), enumerate())
    'validated_by_library': [],  # Passed to stdlib that validates
    
    # Papers #13-16: IC3/PDR (Incremental Inductive Verification)
    'numeric_bounds_from_range': [],  # range() guarantees bounds
    'max_min_protection': [],  # max(x, 1) or min(x, limit) protects
    
    # Papers #17-20: CHC Solving (Horn Clause Constraints)
    'recursive_with_base_case': [],  # Recursive but has proper base case
    'initialization_guarantees': [],  # Variable initialized safely
}

print("="*80)
print("ANALYZING PATTERNS FOR DEEP VERIFICATION")
print("="*80)
print()

for func_name, summary in summaries.items():
    if not hasattr(summary, 'may_trigger'):
        continue
    
    # Pattern 1: Exception caught (Papers #1-4: SOS semantics)
    # If exception is raised but caught, not a real bug
    if hasattr(summary, 'instructions'):
        has_raise = any('RAISE' in str(instr.opname) for instr in summary.instructions)
        has_except = any('SETUP_EXCEPT' in str(instr.opname) or 'SETUP_FINALLY' in str(instr.opname) 
                        for instr in summary.instructions)
        
        if has_raise and has_except:
            for bug_type in summary.may_trigger:
                patterns['exception_caught'].append({
                    'function': func_name,
                    'bug_type': bug_type,
                    'reason': 'Exception raised but caught by except handler',
                    'paper_group': 'Papers #1-4 (SOS)',
                    'improvement': 'Track exception handlers in control flow'
                })
    
    # Pattern 2: isinstance() type narrowing (Papers #5-8: CEGAR)
    if hasattr(summary, 'instructions'):
        has_isinstance = any(
            'isinstance' in str(instr.argval) if hasattr(instr, 'argval') else False
            for instr in summary.instructions
        )
        has_null_ptr = hasattr(summary, 'may_trigger') and 'NULL_PTR' in summary.may_trigger
        
        if has_isinstance and has_null_ptr:
            patterns['type_narrowed_by_isinstance'].append({
                'function': func_name,
                'bug_type': 'NULL_PTR',
                'reason': 'isinstance() check narrows type to non-None',
                'paper_group': 'Papers #5-8 (CEGAR)',
                'improvement': 'Add isinstance() to guard detection'
            })
    
    # Pattern 3: Common stdlib patterns (Papers #9-12: ICE learning)
    if hasattr(summary, 'instructions'):
        safe_patterns = ['len(', 'enumerate(', 'range(', 'zip(']
        has_safe_pattern = any(
            any(pattern in str(instr.argval) for pattern in safe_patterns)
            if hasattr(instr, 'argval') else False
            for instr in summary.instructions
        )
        
        if has_safe_pattern:
            for bug_type in summary.may_trigger:
                if bug_type in ['BOUNDS', 'DIV_ZERO']:
                    patterns['common_idiom_pattern'].append({
                        'function': func_name,
                        'bug_type': bug_type,
                        'reason': f'Uses safe stdlib pattern (len/enumerate/range)',
                        'paper_group': 'Papers #9-12 (ICE)',
                        'improvement': 'Learn invariants from common stdlib usage'
                    })
    
    # Pattern 4: range() guarantees (Papers #13-16: IC3)
    if hasattr(summary, 'instructions'):
        has_range = any(
            'range' in str(instr.argval) if hasattr(instr, 'argval') else False
            for instr in summary.instructions
        )
        has_bounds = hasattr(summary, 'may_trigger') and 'BOUNDS' in summary.may_trigger
        
        if has_range and has_bounds:
            patterns['numeric_bounds_from_range'].append({
                'function': func_name,
                'bug_type': 'BOUNDS',
                'reason': 'range() produces indices within bounds',
                'paper_group': 'Papers #13-16 (IC3)',
                'improvement': 'Infer bounds constraints from range()'
            })
    
    # Pattern 5: max/min protection (Papers #13-16: IC3)
    if hasattr(summary, 'instructions'):
        has_max_min = any(
            ('max' in str(instr.argval) or 'min' in str(instr.argval))
            if hasattr(instr, 'argval') else False
            for instr in summary.instructions
        )
        has_div_zero = hasattr(summary, 'may_trigger') and 'DIV_ZERO' in summary.may_trigger
        
        if has_max_min and has_div_zero:
            patterns['max_min_protection'].append({
                'function': func_name,
                'bug_type': 'DIV_ZERO',
                'reason': 'max(x, 1) or min(x, limit) prevents division by zero',
                'paper_group': 'Papers #13-16 (IC3)',
                'improvement': 'Recognize max/min as constraint predicates'
            })
    
    # Pattern 6: Early initialization (Papers #17-20: CHC)
    if hasattr(summary, 'instructions'):
        has_early_store = False
        has_later_load = False
        store_idx = -1
        
        for i, instr in enumerate(summary.instructions):
            if 'STORE' in str(instr.opname) and store_idx == -1:
                store_idx = i
                has_early_store = True
            elif 'LOAD' in str(instr.opname) and store_idx != -1 and i > store_idx + 3:
                has_later_load = True
        
        if has_early_store and has_later_load:
            has_null_ptr = hasattr(summary, 'may_trigger') and 'NULL_PTR' in summary.may_trigger
            if has_null_ptr:
                patterns['initialization_guarantees'].append({
                    'function': func_name,
                    'bug_type': 'NULL_PTR',
                    'reason': 'Variable initialized early, used later',
                    'paper_group': 'Papers #17-20 (CHC)',
                    'improvement': 'Track initialization in def-use chains'
                })

# Report findings
print("AUGMENTATION OPPORTUNITIES FOR DEEP VERIFICATION:")
print("="*80)
print()

total_fps_catchable = 0
for pattern_name, cases in sorted(patterns.items(), key=lambda x: len(x[1]), reverse=True):
    if cases:
        total_fps_catchable += len(cases)
        example = cases[0]
        print(f"{pattern_name.upper().replace('_', ' ')}:")
        print(f"  Found: {len(cases)} potential FPs")
        print(f"  Paper group: {example['paper_group']}")
        print(f"  Bug types affected: {Counter(c['bug_type'] for c in cases).most_common(3)}")
        print(f"  Improvement needed: {example['improvement']}")
        print(f"  Example: {example['function']}")
        print(f"    → {example['reason']}")
        print()

print(f"Total FPs catchable by deep verification: {total_fps_catchable}")
print()

# Generate specific recommendations
print("="*80)
print("CONCRETE AUGMENTATIONS TO IMPLEMENT")
print("="*80)
print()

recommendations = []

if patterns['common_idiom_pattern']:
    recommendations.append({
        'priority': 'HIGH',
        'papers': '#9-12 (ICE Learning)',
        'title': 'Recognize Safe Stdlib Patterns',
        'description': 'Learn that len(), enumerate(), range() produce safe values',
        'implementation': '''
Add to Layer 3 (ICE Learning):
- len(x) → result >= 0
- enumerate(x) → yields (int >= 0, element)
- range(n) → generates 0 <= i < n
- zip(a, b) → safe parallel iteration
        ''',
        'expected_fps': len(patterns['common_idiom_pattern'])
    })

if patterns['max_min_protection']:
    recommendations.append({
        'priority': 'HIGH',
        'papers': '#13-16 (IC3)',
        'title': 'Constraint Solving for max/min',
        'description': 'Prove max(x, 1) >= 1, min(x, n) <= n',
        'implementation': '''
Add to Layer 4 (IC3/PDR):
- max(x, k) where k > 0 → result >= k (prevents DIV_ZERO)
- min(x, k) → result <= k (prevents BOUNDS overflow)
- Propagate constraints through arithmetic
        ''',
        'expected_fps': len(patterns['max_min_protection'])
    })

if patterns['type_narrowed_by_isinstance']:
    recommendations.append({
        'priority': 'MEDIUM',
        'papers': '#5-8 (CEGAR)',
        'title': 'isinstance() Type Narrowing',
        'description': 'Track type refinement from isinstance() checks',
        'implementation': '''
Add to Layer 2 (CEGAR):
- if isinstance(x, MyClass): → x is not None after this
- if x is not None: → explicit null check
- Refine abstract domain based on type guards
        ''',
        'expected_fps': len(patterns['type_narrowed_by_isinstance'])
    })

if patterns['numeric_bounds_from_range']:
    recommendations.append({
        'priority': 'MEDIUM',
        'papers': '#13-16 (IC3)',
        'title': 'Range Constraint Inference',
        'description': 'Infer bounds from range() and for loops',
        'implementation': '''
Add to Layer 4 (IC3):
- for i in range(n): → 0 <= i < n
- for i in range(start, end): → start <= i < end
- Verify array accesses arr[i] within these bounds
        ''',
        'expected_fps': len(patterns['numeric_bounds_from_range'])
    })

if patterns['exception_caught']:
    recommendations.append({
        'priority': 'LOW',
        'papers': '#1-4 (SOS)',
        'title': 'Exception Handler Analysis',
        'description': 'Track exception control flow',
        'implementation': '''
Add to Layer 1 (SOS):
- Identify try/except blocks
- Propagate that exceptions are caught
- Don't report bugs that can't escape except handler
        ''',
        'expected_fps': len(patterns['exception_caught'])
    })

if patterns['initialization_guarantees']:
    recommendations.append({
        'priority': 'LOW',
        'papers': '#17-20 (CHC)',
        'title': 'Def-Use Chain Analysis',
        'description': 'Prove variable initialized before use',
        'implementation': '''
Add to Layer 5 (CHC):
- Build def-use chains
- Prove every use has a dominating def
- Initialization at function entry counts as def
        ''',
        'expected_fps': len(patterns['initialization_guarantees'])
    })

# Print recommendations sorted by priority and expected impact
for rec in sorted(recommendations, key=lambda x: (
    {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}[x['priority']], 
    -x['expected_fps']
)):
    print(f"[{rec['priority']}] {rec['title']} (Papers {rec['papers']})")
    print(f"  Expected FP reduction: {rec['expected_fps']} bugs")
    print(f"  {rec['description']}")
    print(f"  Implementation:{rec['implementation']}")
    print()

print("="*80)
print("IMPLEMENTATION PLAN")
print("="*80)
print()
print("Phase 1 (Highest ROI):")
print("  1. Safe stdlib patterns (Papers #9-12) - Most common")
print("  2. max/min constraints (Papers #13-16) - DIV_ZERO critical")
print()
print("Phase 2 (Medium ROI):")
print("  3. isinstance() type narrowing (Papers #5-8)")
print("  4. range() bounds inference (Papers #13-16)")
print()
print("Phase 3 (Lower ROI, but improves completeness):")
print("  5. Exception handler tracking (Papers #1-4)")
print("  6. Def-use chain analysis (Papers #17-20)")
print()
print(f"Total potential FP reduction: {total_fps_catchable} additional bugs")
print(f"Current: 377 bugs → Target: {377 - total_fps_catchable} bugs")
print(f"FP reduction: {total_fps_catchable / 377 * 100:.1f}%")
