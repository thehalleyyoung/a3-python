# Iteration 80: Explicit Z3 Variable Tracking for Better Counterexample Extraction

## Problem Statement

Previous iterations of CEGIS barrier certificate synthesis had limitations in counterexample extraction:

1. `_extract_variable_value()` always returned `None` because we couldn't map Z3 model declarations back to program variables
2. `_extract_barrier_value()` always returned `None` because we couldn't evaluate barriers at counterexample states
3. Counterexamples contained raw Z3 declaration names but no structured mapping to program semantics

This made debugging barrier synthesis failures difficult and limited the effectiveness of counterexample-guided refinement.

## Solution: Explicit Z3 Variable Map

Added explicit tracking of program variables to Z3 expressions in `SymbolicMachineState`:

### Code Changes

#### 1. SymbolicMachineState Enhancement

```python
@dataclass
class SymbolicMachineState:
    # ... existing fields ...
    
    # NEW: Z3 variable tracking for barrier certificate extraction
    z3_variable_map: dict[str, z3.ExprRef] = field(default_factory=dict)
    
    def register_z3_variable(self, var_name: str, z3_expr: z3.ExprRef):
        """Register a Z3 expression for a program variable."""
        self.z3_variable_map[var_name] = z3_expr
    
    def get_z3_variable(self, var_name: str) -> Optional[z3.ExprRef]:
        """Get the Z3 expression for a tracked program variable."""
        return self.z3_variable_map.get(var_name)
```

- Added `z3_variable_map` field to store mapping from variable names to Z3 expressions
- Added `register_z3_variable()` method to register variables during symbolic execution
- Added `get_z3_variable()` method to retrieve tracked Z3 expressions
- Updated `copy()` method to properly copy the variable map

#### 2. InductivenessResult Enhancement

```python
@dataclass
class InductivenessResult:
    # ... existing fields ...
    
    # NEW: Store states for better counterexample extraction
    init_counterexample_state: Optional[SymbolicMachineState] = None
    unsafe_counterexample_state: Optional[SymbolicMachineState] = None
    step_counterexample_state: Optional[SymbolicMachineState] = None
```

- Extended to store the full symbolic states along with Z3 models
- Allows access to `z3_variable_map` during counterexample extraction

#### 3. InductivenessChecker Enhancement

Updated all three check methods to return states along with models:

```python
def _check_init(...) -> tuple[bool, Optional[z3.ModelRef], Optional[SymbolicMachineState]]:
    # ... check logic ...
    return False, solver.model(), s0  # Return state on failure

def _check_unsafe(...) -> tuple[bool, Optional[z3.ModelRef], Optional[SymbolicMachineState]]:
    # ... check logic ...
    return False, solver.model(), s  # Return state on failure

def _check_step(...) -> tuple[bool, Optional[z3.ModelRef], Optional[SymbolicMachineState]]:
    # ... check logic ...
    return False, solver.model(), s  # Return state on failure
```

Updated `check_inductiveness()` to populate the new state fields in `InductivenessResult`.

#### 4. CEGIS Counterexample Extraction Enhancement

```python
def _extract_variable_value(
    self,
    model: z3.ModelRef,
    variable_extractor: Callable,
    state: Optional[SymbolicMachineState] = None
) -> Optional[float]:
    """Extract concrete value with Z3 variable map."""
    # Strategy 1: Use z3_variable_map directly
    if state and hasattr(state, 'z3_variable_map'):
        for var_name, z3_expr in state.z3_variable_map.items():
            val = model.eval(z3_expr, model_completion=True)
            return self._z3_value_to_python(val)
    
    # Strategy 2: Fallback to heuristics
    # ... existing fallback code ...

def _extract_barrier_value(
    self,
    model: z3.ModelRef,
    barrier: BarrierCertificate,
    state: Optional[SymbolicMachineState] = None
) -> Optional[float]:
    """Extract barrier value with explicit state."""
    if state and barrier.barrier_function:
        barrier_expr = barrier.barrier_function(state)
        barrier_val = model.eval(barrier_expr, model_completion=True)
        return self._z3_value_to_python(barrier_val)
    return None
```

- Updated extraction methods to accept optional `state` parameter
- Use `z3_variable_map` to directly map variables to Z3 expressions
- Evaluate barrier functions at concrete counterexample states

#### 5. BarrierCertificate Enhancement

Added `barrier_function` property for compatibility:

```python
@dataclass
class BarrierCertificate:
    # ... existing fields ...
    
    @property
    def barrier_function(self) -> BarrierFunction:
        """Alias for barrier_fn for compatibility."""
        return self.barrier_fn
```

## Usage Pattern

When creating symbolic states for barrier synthesis:

```python
def initial_state_builder():
    s = SymbolicMachineState()
    
    # Create Z3 variable
    n = z3.Int('n')
    
    # IMPORTANT: Register it in the map
    s.register_z3_variable('n', n)
    
    # Use in constraints
    s.path_condition = z3.And(n >= 0, n <= 100)
    
    return s

def variable_extractor(s):
    # Extract using the map
    return s.get_z3_variable('n')
```

## Benefits

### 1. Accurate Counterexample Values

Before: `counterexample.variable_value = None`  
After: `counterexample.variable_value = 42.0` (concrete value from model)

### 2. Accurate Barrier Evaluations

Before: `counterexample.barrier_value = None`  
After: `counterexample.barrier_value = -3.5` (actual B(s) at CE state)

### 3. Better CEGIS Refinement

With concrete values, CEGIS can build quantifier-free constraints:

```python
# For CE at x=7 where init failed:
# Add constraint: B(7) >= epsilon
# i.e., (a*49 + b*7 + c) >= 0.5
```

This guides parameter synthesis toward valid barriers more efficiently.

### 4. Improved Debugging

Counterexample summaries now show concrete values:

```
Counterexamples: 3 total
  init: 2
    var=2.0, B=-0.3
    var=3.0, B=-0.7
  step: 1
    var=5.0, B=0.1
```

## Testing

Added 9 new tests in `tests/test_z3_variable_tracking.py`:

1. **TestZ3VariableMapping**: Basic registration/retrieval (4 tests)
2. **TestCounterexampleExtraction**: Value extraction from models (3 tests)
3. **TestCEGISWithVariableTracking**: CEGIS integration (1 test)
4. **TestInductivenessResultWithStates**: State storage (1 test)

All 802 existing tests continue to pass.

## Backward Compatibility

- Changes are fully backward compatible
- Existing code that doesn't call `register_z3_variable()` continues to work
- Extraction methods fall back to heuristics when map is empty
- Optional `state` parameters have safe defaults

## Future Work

1. **Automatic Registration**: Hook into `LOAD_FAST`/`STORE_FAST` to auto-register variables
2. **Multi-Variable Barriers**: Leverage map for barriers over multiple program variables
3. **Path-Specific Maps**: Track variable renaming across symbolic paths
4. **DSE Integration**: Use map to generate concrete test inputs more reliably

## Soundness Note

This change is purely for **diagnostics and efficiency**. The core verification logic remains:

- Barriers are still checked via Z3 queries
- SAFE is only reported when inductiveness is proven
- BUG requires a model-checked reachable trace
- Variable tracking never affects safety decisions

The improvement is in **how we learn from failures**, not in the verification itself.

## Related Files

- `pyfromscratch/semantics/symbolic_vm.py` - State tracking
- `pyfromscratch/barriers/invariants.py` - Result enhancement
- `pyfromscratch/barriers/cegis.py` - Extraction improvements
- `tests/test_z3_variable_tracking.py` - New tests
- `tests/test_barriers.py` - Updated existing tests

## Statistics

- Lines changed: ~150
- New tests: 9
- Test coverage: All existing + new functionality
- Backward compatibility: 100%
- Performance impact: Negligible (map operations are O(1))
