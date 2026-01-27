# Iteration 127: Python 3.14 Opcode Implementation

## Motivation

Quick scan revealed **462 out of 695 files (66%)** in tier 2 repos use new Python 3.14 optimization opcodes that were unimplemented, causing analysis to fail with UNKNOWN verdicts.

## Opcodes Implemented

### 1. LOAD_FAST_BORROW_LOAD_FAST_BORROW (opcode 87)

**Purpose**: Optimization that loads two consecutive local variables onto the stack in a single instruction.

**Semantics**: 
- Pushes `locals[var1]` then `locals[var2]` onto operand stack
- Raises `UnboundLocalError` if either variable is unbound
- Equivalent to two sequential `LOAD_FAST` instructions

**Implementation**: Lines 1043-1090 in `symbolic_vm.py`

**Argument encoding**: 
- Low byte (bits 0-7): index of first variable
- High byte (bits 8-15): index of second variable

### 2. STORE_FAST_STORE_FAST (opcode 114)

**Purpose**: Optimization that stores two stack values into two consecutive local variables in a single instruction.

**Semantics**:
- Pops TOS → `locals[var2]`
- Pops TOS1 → `locals[var1]`
- Raises `StackUnderflow` if stack has < 2 values
- Equivalent to two sequential `STORE_FAST` instructions
- Note: reverse order (TOS goes to var2, not var1)

**Implementation**: Lines 1092-1132 in `symbolic_vm.py`

**Argument encoding**: Same as LOAD_FAST_BORROW_LOAD_FAST_BORROW

## Impact Analysis

**Files affected in tier 2 repos**:
- black: 51/96 files (53%)
- httpie: 58/100 files (58%)
- django: 74/100 files (74%)
- scikit-learn: 64/100 files (64%)
- ansible: 73/100 files (73%)
- numpy: 70/100 files (70%)
- pandas: 72/99 files (73%)

**Total**: 462/695 files (66.5%)

## Verification

1. Full test suite: 926 passed (same as before)
2. Manual verification on pandas files with opcodes: UNKNOWN → BUG/SAFE
3. No regressions in existing functionality

## Soundness

Both opcodes are purely syntactic optimizations - they have identical semantics to their decomposed forms. Implementation maintains:
- Sound exception modeling (UnboundLocalError, StackUnderflow)
- Correct stack ordering
- User function tracking for intraprocedural analysis

## Files Changed

- `pyfromscratch/semantics/symbolic_vm.py`: Added opcode implementations
- Removed opcodes from "problematic" list in inlining check
- `State.json`: Updated opcode list
- `docs/notes/iteration-127-python314-opcodes.md`: This file

## Next Steps

This unblocks analysis of ~66% of tier 2 files. Expected improvements:
- Reduced UNKNOWN rate across all repos
- More complete bug detection coverage
- Enables full tier 2 rescan with accurate results
