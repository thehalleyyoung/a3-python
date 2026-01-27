# Context-Sensitive Interprocedural Analysis (k-CFA)

## Overview

PythonFromScratch now supports **k-CFA context sensitivity** for interprocedural taint analysis. This improves precision by distinguishing different calling contexts when analyzing functions.

## What is k-CFA?

k-CFA (k-Call-string with Flow-sensitivity Approach) is a program analysis technique that tracks the last k call sites in the call stack. This allows the analyzer to distinguish between:

- Different calls to the same function from different locations
- Different paths through recursive functions
- Multiple callers passing different data to the same callee

## Context Depth Levels

### 0-CFA (Context-Insensitive)
- **Default behavior**: All calls to the same function are merged
- **Pros**: Fast, scales well to large codebases
- **Cons**: May produce false positives due to merging clean and tainted paths

### 1-CFA (Call-Site Sensitive)
- **Tracks**: Last 1 call site
- **Pros**: Good balance of precision and performance, eliminates many false positives
- **Cons**: Slightly slower than 0-CFA, may not distinguish deep call chains

### 2-CFA (Deeper Context)
- **Tracks**: Last 2 call sites
- **Pros**: More precise for deep call chains, better handling of wrapper functions
- **Cons**: More computational cost, potential for state explosion

### k-CFA (Arbitrary Depth)
- **Tracks**: Last k call sites
- **Note**: Higher values of k provide diminishing returns and may cause performance issues

## Usage

### CLI

```bash
# Context-insensitive (default, fastest)
python3 -m pyfromscratch.cli file.py --interprocedural

# Call-site sensitive (recommended for security analysis)
python3 -m pyfromscratch.cli file.py --interprocedural --context-depth 1

# Deeper context (for complex call chains)
python3 -m pyfromscratch.cli file.py --interprocedural --context-depth 2

# Project-wide analysis with 1-CFA
python3 -m pyfromscratch.cli project/ --interprocedural --context-depth 1
```

### Python API

```python
from pathlib import Path
from pyfromscratch.semantics.sota_interprocedural import analyze_file_interprocedural

# Context-insensitive
violations = analyze_file_interprocedural(
    Path("file.py"),
    context_depth=0
)

# 1-CFA (recommended)
violations = analyze_file_interprocedural(
    Path("file.py"),
    context_depth=1
)

# 2-CFA
violations = analyze_file_interprocedural(
    Path("file.py"),
    context_depth=2
)
```

### Analyzer Class

```python
from pyfromscratch.analyzer import Analyzer
from pathlib import Path

# Create analyzer with context sensitivity
analyzer = Analyzer(
    verbose=True,
    context_depth=1  # 1-CFA
)

# Analyze file or project
result = analyzer.scan_sota_interprocedural(Path("file.py"))
```

## Example: Precision Improvement

Consider this code where the same function is called with both tainted and clean data:

```python
def identity(x):
    return x

def main():
    # Call 1: tainted input
    user_input = input("Enter: ")
    result1 = identity(user_input)  # Call site A
    subprocess.run(result1, shell=True)  # BUG!
    
    # Call 2: clean literal
    clean = "safe"
    result2 = identity(clean)  # Call site B
    print(result2)  # Not a bug
```

**With 0-CFA (context-insensitive)**:
- Both calls to `identity` merge
- The function may be over-approximated as always returning tainted data
- Could produce false positives

**With 1-CFA (call-site sensitive)**:
- Call site A and call site B are distinguished
- `result1` is correctly identified as tainted
- `result2` is correctly identified as clean
- Only the genuine bug is reported

## Implementation Details

### CallContext Data Structure

```python
@dataclass(frozen=True)
class CallContext:
    call_chain: Tuple[str, ...]
    
    def empty() -> CallContext:
        """Create empty context (0-CFA)."""
        return CallContext(call_chain=())
    
    def extend(call_site: str, k: int) -> CallContext:
        """Extend context with new call site (k-CFA)."""
        new_chain = self.call_chain + (call_site,)
        if len(new_chain) > k:
            new_chain = new_chain[-k:]  # Keep only last k
        return CallContext(call_chain=new_chain)
```

### Call Site Identifiers

Call sites are identified by `{function_name}:{line_number}`:
- Example: `main:42` = call at line 42 in function `main`
- Unique identifier for each call location
- Used to track calling context

### Fact Representation

Facts are now keyed by context:
- **Old (0-CFA)**: `(func_name, slot_type, slot_idx)`
- **New (k-CFA)**: `(context, func_name, slot_type, slot_idx)`

### Context Matching

**Call edges**: Extend context when entering callee
```python
callee_context = context.extend(call_site_id, k=context_depth)
```

**Return edges**: Check context matches and pop call site
```python
if context.call_chain[-1] == call_site_id:
    caller_context = CallContext(call_chain=context.call_chain[:-1])
```

## Performance Considerations

| Context Depth | Precision | Speed | Memory | Recommended Use Case |
|---------------|-----------|-------|--------|---------------------|
| 0-CFA         | Low       | Fast  | Low    | Quick scans, large codebases |
| 1-CFA         | Good      | Good  | Medium | Security analysis, general use |
| 2-CFA         | High      | OK    | Higher | Deep call chains, wrappers |
| 3+ CFA        | Very High | Slow  | High   | Specialized analysis only |

## Recommendations

### For Most Use Cases
Use **1-CFA** (`--context-depth 1`):
- Good balance of precision and performance
- Eliminates most context-related false positives
- Handles common patterns (wrappers, helpers)

### For Large Codebases
Use **0-CFA** (`--context-depth 0`):
- Fastest analysis
- Lower memory usage
- Accept some false positives for speed

### For Deep Call Chains
Use **2-CFA** (`--context-depth 2`):
- Better precision for multi-level wrappers
- Handle complex frameworks (Django, Flask)
- Worth the extra cost for security-critical code

## Testing

Context sensitivity is validated by 9 comprehensive tests in:
- `tests/test_context_sensitivity.py` (8 tests)
- `tests/test_context_precision_demo.py` (1 demonstration)

Run tests:
```bash
pytest tests/test_context_sensitivity.py -v
```

## References

- **Original Paper**: Shivers, O. "Control-Flow Analysis of Higher-Order Languages" (1991)
- **IDE Algorithm**: Sagiv, Reps, Horwitz. "Precise Interprocedural Dataflow Analysis with Applications to Constant Propagation" (1996)
- **Implementation**: `pyfromscratch/semantics/sota_interprocedural.py`

## See Also

- [ITERATION_542_SUMMARY.md](../ITERATION_542_SUMMARY.md) - Implementation details
- [python-barrier-certificate-theory.md](../python-barrier-certificate-theory.md) - Theoretical foundation
- [CODEQL_PARITY_SOTA_MATH_PLAN.md](../CODEQL_PARITY_SOTA_MATH_PLAN.md) - Interprocedural analysis plan
