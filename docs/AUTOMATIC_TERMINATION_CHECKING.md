# Automatic Termination Checking

## Overview

The termination checking feature automatically verifies whether loops in Python code terminate by synthesizing ranking functions. This implements barrier-certificate-theory.tex §8 (Ranking Functions) and provides formal guarantees about program termination.

## How It Works

### 1. Loop Detection

The system uses CFG (Control Flow Graph) analysis to identify loops:
- **Back-edges**: Edges where the target dominates the source
- **Loop headers**: Targets of back-edges (entry point of loop)
- **Loop body**: All basic blocks dominated by the header that reach back-edge sources

```python
from pyfromscratch.cfg.loop_analysis import extract_loops

loops = extract_loops(code_obj)
for loop in loops:
    print(f"Loop at offset {loop.header_offset}")
    print(f"  Variables: {loop.loop_variables}")
    print(f"  Pattern: {identify_loop_pattern(loop)}")
```

### 2. Variable Extraction

For each loop, the system identifies:
- **Modified variables**: Variables assigned within the loop body (`STORE_FAST`, `STORE_NAME`, etc.)
- **Compared variables**: Variables used in comparisons (potential loop bounds)
- **Loop variables**: Union of modified and compared variables

These form the basis for ranking function synthesis.

### 3. Ranking Function Synthesis

The system attempts to synthesize a ranking function R: S → ℝ≥0 that proves termination:

**Requirements**:
1. **BoundedBelow**: ∀s. R(s) ≥ 0
2. **Decreasing**: ∀s,s'. (s →loop s') ⇒ R(s') < R(s)

**Template Enumeration** (simplest first):
1. Single counters: R = var
2. Inverted counters: R = bound - counter
3. Linear combinations: R = c₀ + c₁·v₁ + c₂·v₂
4. Lexicographic: (R₁, R₂, ...) for nested loops
5. Quadratic: R = c₀ + c₁·var + c₂·var²

Z3 verifies each template until a valid ranking function is found.

### 4. Verdicts

- **TERMINATES**: Found a ranking function with Z3-verified proof
  - Includes the ranking function and verification details
  - Proves the loop cannot run forever
  
- **NON_TERMINATION**: Found a concrete counterexample of infinite loop
  - Requires witnessing an actual non-terminating execution
  - Very rare in practice (most infinite loops get UNKNOWN)
  
- **UNKNOWN**: Could not find a ranking function
  - Does NOT prove non-termination
  - May be due to template budget, complex ranking needed, or truly non-terminating

## API

### Basic Usage

```python
from pyfromscratch.semantics.symbolic_vm import SymbolicVM

# Compile your code
code = compile("""
def countdown(n):
    while n > 0:
        n -= 1
""", "<test>", "exec")

# Extract function code object
func_code = code.co_consts[0]

# Check termination
vm = SymbolicVM()
results = vm.check_termination(func_code)

# Process results
for result in results:
    if result.is_safe():
        print(f"✓ Loop terminates")
        print(f"  Ranking: {result.ranking.name}")
        print(f"  Variables: {result.ranking.variables}")
    elif result.is_bug():
        print(f"✗ Non-termination detected")
    else:
        print(f"? Unknown (no ranking found)")
```

### Advanced Configuration

```python
from pyfromscratch.barriers.ranking_synthesis import RankingSynthesisConfig

# Configure synthesis parameters
config = RankingSynthesisConfig(
    max_templates=100,              # Try more templates
    timeout_per_template_ms=10000,  # Longer timeout per template
    coefficient_range=(-10, 10, 0.5),  # Finer coefficient search
    max_lexicographic_depth=4       # Deeper lexicographic rankings
)

# Use custom config
results = vm.check_termination(func_code, config=config)
```

### Direct Loop Analysis

```python
from pyfromscratch.cfg.loop_analysis import extract_loops, identify_loop_pattern
from pyfromscratch.semantics.termination_integration import TerminationIntegrator

# Extract loops manually
loops = extract_loops(code_obj)

# Analyze each loop
integrator = TerminationIntegrator(config)
for loop in loops:
    pattern = identify_loop_pattern(loop)
    print(f"Loop pattern: {pattern}")
    print(f"Variables: {loop.loop_variables}")
```

## Examples

### Example 1: Simple Countdown

```python
def countdown(n):
    while n > 0:
        n -= 1
```

**Result**: TERMINATES with R = n
- BoundedBelow: n ≥ 0 (from loop guard)
- Decreasing: n' = n - 1 < n

### Example 2: Bounded Counter

```python
def countup(n):
    i = 0
    while i < n:
        i += 1
```

**Result**: TERMINATES with R = n - i
- BoundedBelow: n - i ≥ 0 (from i < n)
- Decreasing: n - i' = n - (i + 1) = (n - i) - 1 < n - i

### Example 3: Complex Multi-Variable

```python
def complex_loop(a, b):
    while a > 0 and b > 0:
        if a > b:
            a -= 1
        else:
            b -= 1
```

**Result**: TERMINATES with R = a + b
- BoundedBelow: a + b ≥ 0 (both ≥ 0)
- Decreasing: Either a' = a - 1 or b' = b - 1, so a' + b' < a + b

### Example 4: Nested Loops

```python
def nested(m, n):
    for i in range(m):
        for j in range(n):
            pass
```

**Result**: TERMINATES with lexicographic ranking (m - i, n - j)
- Outer loop: R₁ = m - i decreases
- Inner loop: R₂ = n - j decreases
- When inner resets, outer decreases

## Limitations

1. **Template-based**: Only finds ranking functions in the template set
   - May miss complex rankings (exponential, logarithmic, etc.)
   - Unknown verdicts don't prove non-termination

2. **Conservative back-edge encoding**: 
   - Current implementation uses simple "variable changes" encoding
   - More precise encoding requires dataflow analysis

3. **Loop extraction accuracy**:
   - Relies on CFG back-edge detection
   - May miss implicit loops (recursion, generators)

4. **Interprocedural termination**:
   - Currently intraprocedural only
   - Function calls are not analyzed recursively

## Future Enhancements

1. **Better back-edge encoding**: Use dataflow analysis to extract precise loop updates
2. **Recursive termination**: Extend to function call chains
3. **Generator/async termination**: Handle Python-specific control flow
4. **Custom templates**: Allow user-defined ranking function templates
5. **Counterexample-guided synthesis**: Use failed attempts to refine search

## Testing

Run the termination tests:

```bash
pytest tests/test_termination_integration.py -v
pytest tests/test_ranking_synthesis.py -v
pytest tests/test_unsafe_non_termination.py -v
```

All tests should pass:
- 7 termination integration tests
- 10 ranking synthesis tests
- 15 non-termination detection tests

## References

- `barrier-certificate-theory.tex` §8: Ranking Functions
- `pyfromscratch/cfg/loop_analysis.py`: Loop extraction
- `pyfromscratch/semantics/termination_integration.py`: VM integration
- `pyfromscratch/barriers/ranking_synthesis.py`: Template enumeration
- `pyfromscratch/barriers/ranking.py`: Ranking function verification
