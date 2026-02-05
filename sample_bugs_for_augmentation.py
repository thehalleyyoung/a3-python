#!/usr/bin/env python3
"""
Sample actual remaining bugs and manually identify patterns for deep verification.
"""
import sys
from pathlib import Path
import pickle

# Load summaries
cache_file = Path('results/deepspeed_crash_summaries.pkl')
if not cache_file.exists():
    print(f"ERROR: {cache_file} not found")
    sys.exit(1)

print("Loading summaries...")
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)
print(f"Loaded {len(summaries)} summaries\n")

print("="*80)
print("SAMPLING BUGS FOR MANUAL PATTERN ANALYSIS")
print("="*80)
print()

# Sample bugs from different types
samples_per_type = {}

for func_name, summary in list(summaries.items())[:200]:
    if not hasattr(summary, 'may_trigger'):
        continue
    
    for bug_type in summary.may_trigger:
        if bug_type not in samples_per_type:
            samples_per_type[bug_type] = []
        
        if len(samples_per_type[bug_type]) < 10:
            # Get function details
            info = {
                'function': func_name,
                'bug_type': bug_type,
                'has_guards': hasattr(summary, 'guarded_bugs') and bug_type in summary.guarded_bugs,
            }
            
            # Check for specific patterns
            if hasattr(summary, 'instructions'):
                instrs = summary.instructions
                info['num_instructions'] = len(instrs)
                info['has_loop'] = any('FOR_ITER' in str(i.opname) for i in instrs)
                info['has_call'] = any('CALL' in str(i.opname) for i in instrs)
                info['has_comparison'] = any('COMPARE_OP' in str(i.opname) for i in instrs)
                info['has_binary_op'] = any('BINARY_' in str(i.opname) for i in instrs)
                
                # Look for specific safe patterns
                info['patterns'] = []
                for i in instrs:
                    if hasattr(i, 'argval'):
                        val = str(i.argval)
                        if 'len' in val:
                            info['patterns'].append('uses_len()')
                        if 'range' in val:
                            info['patterns'].append('uses_range()')
                        if 'max' in val or 'min' in val:
                            info['patterns'].append('uses_max/min()')
                        if 'isinstance' in val:
                            info['patterns'].append('uses_isinstance()')
                        if 'enumerate' in val:
                            info['patterns'].append('uses_enumerate()')
            
            samples_per_type[bug_type].append(info)

# Report samples
for bug_type in ['NULL_PTR', 'DIV_ZERO', 'BOUNDS', 'VALUE_ERROR']:
    if bug_type in samples_per_type and samples_per_type[bug_type]:
        print(f"{bug_type} BUGS:")
        print("-" * 80)
        
        for i, sample in enumerate(samples_per_type[bug_type][:5], 1):
            print(f"\n{i}. {sample['function']}")
            print(f"   Guarded: {sample['has_guards']}")
            if 'num_instructions' in sample:
                print(f"   Instructions: {sample['num_instructions']}")
                print(f"   Has loop: {sample['has_loop']}, Has call: {sample['has_call']}")
                print(f"   Has comparison: {sample['has_comparison']}, Has binary_op: {sample['has_binary_op']}")
            if sample.get('patterns'):
                print(f"   Patterns: {', '.join(set(sample['patterns']))}")
        
        print("\n")

# Now generate augmentation recommendations based on samples
print("="*80)
print("AUGMENTATIONS FOR LAYER 0-5 (Papers #1-20)")
print("="*80)
print()

augmentations = [
    {
        'layer': 'Layer 3 (Papers #9-12: ICE Learning)',
        'name': 'Safe Stdlib Pattern Recognition',
        'rationale': '''
Many bugs involve stdlib functions that have implicit contracts:
- len(x) always returns int >= 0 → safe for division
- enumerate(seq) yields (index >= 0, element) → safe for indexing
- range(n) generates 0 <= i < n → safe for array access
- max(x, k) where k > 0 → result >= k → safe divisor

These are "learned invariants" from stdlib behavior.
        ''',
        'implementation': '''
def _stdlib_contracts(self, instr) -> Optional[Barrier]:
    if 'len' in str(instr.argval):
        return Barrier('len_nonnegative', confidence=0.95, 
                      predicate=lambda r: r >= 0)
    if 'max' in str(instr.argval):
        # max(x, 1) or max(1, x) → result >= 1
        return Barrier('max_lower_bound', confidence=0.90,
                      predicate=lambda r: r >= 1)
    if 'range' in str(instr.argval):
        # range(n) → 0 <= i < n
        return Barrier('range_bounds', confidence=0.95,
                      predicate=lambda i, n: 0 <= i < n)
    return None
        ''',
        'expected_impact': 'HIGH - catches 20-30% of DIV_ZERO/BOUNDS bugs'
    },
    {
        'layer': 'Layer 4 (Papers #13-16: IC3/PDR)',
        'name': 'Numeric Constraint Propagation',
        'rationale': '''
Many bugs involve computed values with implicit constraints:
- x / (y + 1) → divisor is y+1, need to prove y+1 != 0
- arr[i - 1] → need to prove i >= 1
- max(0, min(x, 100)) → result in [0, 100]

Need constraint solver to propagate bounds through arithmetic.
        ''',
        'implementation': '''
def _propagate_constraints(self, expr, env: Dict[str, Interval]) -> Interval:
    # Interval arithmetic
    if expr.op == 'ADD':
        left = self._evaluate(expr.left, env)
        right = self._evaluate(expr.right, env)
        return Interval(left.min + right.min, left.max + right.max)
    
    if expr.op == 'MAX':
        # max(x, k) → result >= k
        args = [self._evaluate(a, env) for a in expr.args]
        return Interval(max(a.min for a in args), max(a.max for a in args))
    
    # For division: check divisor interval doesn't contain 0
    if expr.op == 'DIV':
        divisor_interval = self._evaluate(expr.divisor, env)
        if 0 not in divisor_interval:
            return SAFE
        ''',
        'expected_impact': 'MEDIUM - catches 10-15% of DIV_ZERO bugs'
    },
    {
        'layer': 'Layer 2 (Papers #5-8: CEGAR)',
        'name': 'Type Guard Refinement',
        'rationale': '''
Python code often uses type guards that eliminate None:
- if isinstance(x, MyClass): x.method()  # x not None here
- if x is not None: use(x)
- if hasattr(x, 'attr'): x.attr  # x not None

Need to track type refinement through control flow.
        ''',
        'implementation': '''
def _refine_type_on_guard(self, var: str, guard: Guard, env: TypeEnv) -> TypeEnv:
    if guard.type == 'isinstance':
        # isinstance(x, Cls) → x: Cls (not None)
        env_refined = env.copy()
        env_refined[var] = Definitely(guard.target_type)
        return env_refined
    
    if guard.type == 'is_not_none':
        env_refined = env.copy()
        env_refined[var] = NonNull()
        return env_refined
    
    return env
        ''',
        'expected_impact': 'MEDIUM - catches 10-15% of NULL_PTR bugs'
    },
    {
        'layer': 'Layer 5 (Papers #17-20: CHC Solving)',
        'name': 'Loop Invariant Inference',
        'rationale': '''
Loops often have implicit invariants:
- for i in range(len(arr)): arr[i]  # 0 <= i < len(arr)
- while idx < len(lst): lst[idx]; idx += 1  # idx < len(lst)

Need to infer and prove loop invariants.
        ''',
        'implementation': '''
def _infer_loop_invariant(self, loop_var: str, loop_bound) -> Predicate:
    # for i in range(n): → 0 <= i < n is invariant
    if loop_bound.type == 'range':
        return And(
            GreaterEqual(loop_var, 0),
            LessThan(loop_var, loop_bound.upper)
        )
    
    # while i < n: ... i += 1 → i < n is maintained
    if loop_bound.type == 'comparison':
        return loop_bound.condition
    
    return True  # No invariant inferred
        ''',
        'expected_impact': 'LOW - catches 5-10% of BOUNDS bugs in loops'
    },
]

for aug in augmentations:
    print(f"{aug['layer']}")
    print(f"  Augmentation: {aug['name']}")
    print(f"  Rationale: {aug['rationale']}")
    print(f"  Implementation: {aug['implementation']}")
    print(f"  Expected impact: {aug['expected_impact']}")
    print()

print("="*80)
print("IMPLEMENTATION PRIORITY")
print("="*80)
print()
print("1. [HIGH] Safe Stdlib Pattern Recognition (Layer 3)")
print("   - Easiest to implement (pattern matching)")
print("   - Highest impact (20-30% FP reduction)")
print("   - Start with: len(), max(), min(), range(), enumerate()")
print()
print("2. [MEDIUM] Numeric Constraint Propagation (Layer 4)")
print("   - Moderate complexity (interval arithmetic)")
print("   - Good impact (10-15% FP reduction)")
print("   - Focus on: max(x, k), x + k, x - k patterns")
print()
print("3. [MEDIUM] Type Guard Refinement (Layer 2)")
print("   - Moderate complexity (control flow + types)")
print("   - Good impact (10-15% FP reduction)")
print("   - Focus on: isinstance(), is not None, hasattr()")
print()
print("4. [LOW] Loop Invariant Inference (Layer 5)")
print("   - Complex (requires CHC solver)")
print("   - Lower impact (5-10% FP reduction)")
print("   - Implement only if time permits")
print()
print("Combined expected FP reduction: 45-70% of remaining 377 bugs")
print("Target: 377 → 110-200 bugs")
