# Iteration 108: BUILD_STRING Opcode Implementation

## Context
NumPy bug analysis (iteration 104) identified 5 missing opcodes causing false positives. BUILD_STRING is #4 in priority, used for f-string assembly after FORMAT_SIMPLE operations.

## Implementation

### Semantic Model
BUILD_STRING concatenates N formatted strings from the stack into a single string:
- **Stack**: `str1, str2, ..., strN → concatenated_str`
- **argval**: N (number of strings to pop and concatenate)
- **Bytecode pattern**: `LOAD a, FORMAT_SIMPLE, LOAD b, FORMAT_SIMPLE, BUILD_STRING 2`

### Bug Detection
1. **NULL_PTR**: None in string concatenation (TypeError in CPython)
2. **TYPE_CONFUSION**: Non-string types where strings expected

### Conservative Over-Approximation
Like other string operations, we create a fresh symbolic string ID representing the concatenation result. Precise string content tracking is avoided for scalability (Z3 theory of strings is expensive).

### Code Changes
**File**: `pyfromscratch/semantics/symbolic_vm.py`
- Added `BUILD_STRING` handler after FORMAT_SIMPLE
- Stack validation (N items)
- Type checking for None and non-string inputs
- Fresh symbolic string allocation for result
- Proper instruction pointer advancement

## Testing
**File**: `tests/test_build_string.py`
- 6 tests covering:
  - Basic f-string compilation
  - Single and multiple interpolations
  - Literal + expression mixing
  - Nested expressions
  - Function usage patterns

**Results**: 6/6 pass

## NumPy Opcode Progress
- ✅ EXTENDED_ARG (iteration 105)
- ✅ CONTAINS_OP (iteration 106)
- ✅ DICT_UPDATE (iteration 107)
- ✅ BUILD_STRING (iteration 108) ← current
- ⏳ LOAD_FAST_BORROW (priority #5)

4/5 missing opcodes now complete. Ready for NumPy rescan after next opcode.

## State Updates
- Added BUILD_STRING to implemented_opcodes list
- Tests: 6 pass
- Changed files: symbolic_vm.py, test_build_string.py, State.json
