# Iteration 56: LOAD_CONST Support for Ellipsis and Slice Types

## Goal
Implement LOAD_CONST support for ellipsis (`...`) and slice objects to reduce false PANIC bugs in public repo scanning.

## Background
During DSE validation in iteration 55, we discovered that many public repo files use ellipsis (particularly in type stubs and protocols) and slice objects in subscripting operations. The absence of these types in LOAD_CONST was causing NotImplementedError crashes, leading to false PANIC bug reports.

## Changes Made

### 1. Extended ValueTag Enum (`pyfromscratch/z3model/values.py`)
- Added `ELLIPSIS = 9` to represent the ellipsis singleton
- Added `SLICE = 10` to represent slice objects

### 2. Added Factory Methods (`pyfromscratch/z3model/values.py`)
- `SymbolicValue.ellipsis()`: Creates a symbolic ellipsis value
- `SymbolicValue.slice_obj(obj_id)`: Creates a symbolic slice object reference

### 3. Added Heap Support (`pyfromscratch/z3model/heap.py`)
- Created `SliceObject` dataclass to store slice(start, stop, step) components
- Added `slices` dictionary to `SymbolicHeap` for tracking slice objects
- Implemented `allocate_slice(start, stop, step)` method
- Updated `copy()` method to include slices

### 4. Extended LOAD_CONST Handler (`pyfromscratch/semantics/symbolic_vm.py`)
- Added check for ellipsis singleton: `if val is ...:`
- Added check for slice objects: `elif isinstance(val, slice):`
- Slice objects are allocated in the heap with their start/stop/step components
- Each component is converted to a SymbolicValue (int or none)

## Semantic Correctness

The implementation is semantically faithful:
- **Ellipsis** is a singleton in Python, represented as a value with tag ELLIPSIS
- **Slice objects** are immutable objects with three attributes (start, stop, step), each can be int or None
- Slice syntax `lst[1:4:2]` compiles to `LOAD_CONST` with a slice object, then `BINARY_OP` for subscript
- The heap representation allows reasoning about slice object identity and attributes

## Testing
Created `tests/test_ellipsis_slice.py` with 4 tests:
1. `test_ellipsis_constant`: Verify ellipsis loads without error
2. `test_slice_constant_in_subscript`: Basic slice syntax `lst[1:3]`
3. `test_slice_with_step`: Slice with step `lst[::2]`
4. `test_slice_negative_indices`: Negative indices `lst[-3:-1]`

All tests pass. Full test suite: 608 passed, 10 skipped, 15 xfailed, 12 xpassed.

## Impact on Bug Detection

This change is defensive - it prevents false PANICs from NotImplementedError crashes when analyzing real code. It does not introduce new bug detection capabilities yet (slice semantics in BINARY_OP would need to be expanded for full slice support), but it allows the analyzer to proceed through code that uses ellipsis or slice objects.

## Next Steps
- The BINARY_OP handler for slicing could be enhanced to model slice semantics more precisely
- Ellipsis semantics in various contexts (especially type annotations and protocols) could be modeled
- Consider whether ellipsis or slice patterns should trigger any unsafe conditions
