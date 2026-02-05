# Cross-Module Call Graph Resolution (Iteration 531)

## Problem Statement

Prior to iteration 531, the call graph builder tracked cross-module function calls as "external" even when both the caller and callee were defined within the analyzed project. This prevented interprocedural taint tracking from working across module boundaries.

### Example

Given two modules:

```python
# module_a.py
def source_func():
    import os
    return os.environ.get('USER_INPUT')

# module_b.py
from module_a import source_func

def process_data():
    data = source_func()  # Cross-module call
    # ... use data ...
```

The call from `module_b.process_data` to `module_a.source_func` was tracked as an "external" call, not as an internal edge in the call graph.

## Solution

Added a `resolve_cross_module_calls()` method to the `CallGraph` class that:

1. **Builds lookup maps**: Creates mappings from simple function names to qualified names
2. **Resolves external calls**: For each "external" call, attempts to resolve it to a function in the call graph
3. **Converts to internal edges**: When a match is found, converts the external call to an internal edge
4. **Updates call sites**: Updates CallSite objects with resolved callee names

The resolution happens after all modules are loaded into the call graph, ensuring that cross-module references can be properly resolved.

### Resolution Strategy

The method tries multiple matching strategies in order:

1. **Exact match**: Direct qualified name match
2. **Suffix match**: For qualified names like "module_a.func", check if any function's qualified name ends with this
3. **Simple name match**: If unambiguous (only one function with that name), use it

## Implementation

```python
def resolve_cross_module_calls(self) -> int:
    """
    Resolve external calls that should be internal edges.
    
    After building the call graph from multiple files, some calls
    tracked as "external" are actually to functions in the graph.
    This method resolves those and converts them to internal edges.
    
    Returns:
        Number of external calls resolved to internal edges.
    """
    # ... (see pyfromscratch/cfg/call_graph.py for full implementation)
```

Called from `build_call_graph_from_directory()`:

```python
# After collecting all functions from all modules
resolved = combined.resolve_cross_module_calls()
```

## Impact on Interprocedural Analysis

This fix enables:

1. **Cross-module taint tracking**: Taint can now flow through calls to functions in different modules
2. **Transitive summary computation**: Function summaries correctly account for calls to other modules
3. **Security bug detection**: Multi-module vulnerability patterns can now be detected

### Example: Cross-Module SQL Injection Detection

With the fix, this vulnerability is now detectable:

```python
# database.py
def execute_query(user_input):
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")  # Sink

# controller.py  
from database import execute_query

def process(data):
    return execute_query(data)  # Propagates taint

# web.py
from controller import process

def route(request):
    username = request.args.get('username')  # Source
    return process(username)  # Taint flows: source -> controller -> database -> sink
```

The call chain `web.route -> controller.process -> database.execute_query` is now correctly represented in the call graph, allowing interprocedural taint analysis to detect the vulnerability.

## Testing

Added comprehensive tests in:
- `scripts/test_cross_module_callgraph.py`: Demonstrates the fix
- `scripts/test_cross_module_taint.py`: Tests taint summary computation
- `tests/test_cross_module_taint.py`: Pytest test suite (to be run)

### Test Results

Before fix:
```
Found 0 internal edges
⚠ LIMITATION: Cross-module call tracked as external
```

After fix:
```
Found 1 internal edges:
  module_b.process_data -> module_a.source_func
✓ SUCCESS: Cross-module edge resolved correctly
```

## Limitations

1. **Dynamic calls**: Cannot resolve calls where the callee is computed dynamically
2. **Ambiguous names**: When multiple functions have the same simple name, resolution may be imprecise
3. **Star imports**: Cannot resolve calls from `from module import *`

These limitations are acceptable as they maintain soundness (conservative over-approximation).

## Future Work

1. **Import tracking**: Use the `imports` dictionary in CallGraphBuilder to more precisely resolve cross-module calls
2. **Type inference**: Use type information to resolve method calls on imported objects
3. **Context-sensitive resolution**: Track import context per function for better precision

## Related

- Addresses queue item: "Expand interprocedural taint tracking to handle cross-module function calls with summaries"
- Aligns with CODEQL_PARITY_SOTA_MATH_PLAN.md Phase 2 (Interprocedural transport upgrade)
- Required for detecting cross-module security vulnerabilities in PyGoat and real-world code
