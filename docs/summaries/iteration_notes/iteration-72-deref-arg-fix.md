# Iteration 72: Fixed MAKE_CELL/STORE_DEREF/LOAD_DEREF arg/argval confusion

## Problem

The `test_import_from_typing` test was failing with:
```
TypeError: '<' not supported between instances of 'str' and 'int'
```

This occurred in the MAKE_CELL, STORE_DEREF, and LOAD_DEREF opcode handlers when comparing `var_index < len(frame.code.co_cellvars)`.

## Root Cause

The handlers were using `instr.argval` (the variable name as a string) instead of `instr.arg` (the numeric index). 

For closure-related opcodes like `MAKE_CELL 1 (x)`:
- `instr.arg` = 1 (numeric index we need)
- `instr.argval` = 'x' (variable name, which caused the type error)

## Fix

Changed all three handlers to use `instr.arg` instead of `instr.argval`:
- `MAKE_CELL`: Line ~1758
- `STORE_DEREF`: Line ~1776  
- `LOAD_DEREF`: Line ~1798

## Semantic Impact

This fix ensures proper handling of closure variables across Python 3.11-3.14:
- Cellvars (variables defined in a function and captured by nested functions)
- Freevars (variables from outer scope referenced in a function)

The numeric index is required to correctly:
1. Check whether the variable is a cellvar (index < len(co_cellvars)) or freevar
2. Access the correct slot in frame.cells or frame.freevars

## Testing

- `test_import_from_typing`: Now passes ✓
- All closure tests (13 tests): Still pass ✓
- Full test suite: 717 passed, 10 skipped, 15 xfailed, 12 xpassed

## Anti-Cheating Verification

This fix maintains semantic faithfulness:
- Uses the actual bytecode argument structure (arg vs argval) correctly
- No heuristics or text-based detection
- Preserves the machine-state model of cells/freevars as defined in the Python execution model
