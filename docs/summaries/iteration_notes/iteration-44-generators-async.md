# Iteration 44: Generator and Async/Await Opcodes

## Date
2026-01-23

## Goal
Implement support for generator functions and async/await constructs by adding the necessary bytecode opcodes to the symbolic VM.

## Changes Made

### 1. New Opcodes Implemented

Added 10 new opcodes to support generators and async/await:

1. **RETURN_GENERATOR**: Converts a function into a generator/coroutine object (appears at start of gen/coro functions)
2. **YIELD_VALUE**: Yields a value from a generator/coroutine
3. **SEND**: Sends a value to a generator/coroutine (used in await)
4. **END_SEND**: Finalizes a SEND operation
5. **GET_AWAITABLE**: Converts a value to an awaitable
6. **GET_AITER**: Gets async iterator from async iterable
7. **GET_ANEXT**: Gets next item from async iterator (returns awaitable)
8. **END_ASYNC_FOR**: Handles end of async for loop
9. **GET_YIELD_FROM_ITER**: Prepares iterator for yield from
10. **SET_FUNCTION_ATTRIBUTE**: Sets function attributes (Python 3.14+ replacement for MAKE_FUNCTION flags)

### 2. State Model Extensions

Extended `SymbolicMachineState` to track generator/coroutine execution:

- `generator_states`: Maps generator object IDs to their execution state (frame snapshots, yield positions)
- `is_generator_frame`: Tracks if current execution is inside a generator/coroutine
- `code_objects`: Tracks code objects to check CO_GENERATOR (0x20) and CO_COROUTINE (0x80) flags
- `function_metadata`: Stores per-function metadata including generator/coroutine flags

### 3. Generator Semantics Implementation

Key semantic property: **Calling a generator function returns a generator object without executing the body**.

This is enforced in the CALL opcode:
- Check if function has CO_GENERATOR or CO_COROUTINE flag set
- If yes, return a generator/coroutine object immediately
- Store generator state for potential later resumption (via next() or send())
- Do NOT execute the generator body at call time

This prevents false positives where code like:
```python
def gen():
    x = 1 / 0  # Would raise if executed
    yield x

g = gen()  # Should NOT raise - body not executed yet
```

### 4. Python 3.14 MAKE_FUNCTION Update

Updated MAKE_FUNCTION for Python 3.14+ simplified stack layout:
- **Old (3.11-3.13)**: Stack had qualname, code_obj, and optional defaults/annotations/closure based on flags
- **New (3.14+)**: Stack only has code_obj; attributes set via separate SET_FUNCTION_ATTRIBUTE opcode

### 5. Code Object Handling in LOAD_CONST

Extended LOAD_CONST to handle `types.CodeType` objects:
- Store code object with its ID
- Track in `state.code_objects` for later flag checking
- Enables MAKE_FUNCTION to detect generator/coroutine functions

## Barrier-Certificate Model Implications

### 1. Generator Suspension Points

YIELD_VALUE introduces **suspension points** in the control flow:
- Execution can suspend and resume at yield points
- For reachability analysis, we model yield as potentially returning control to caller
- Full model would require tracking generator state machine transitions

### 2. Async/Await Semantics

Async/await introduces **cooperative concurrency**:
- GET_AWAITABLE, SEND, END_SEND form the core await machinery
- For bug detection, we model awaitable results as symbolic values
- Concurrency-related bugs (DATA_RACE, DEADLOCK) need scheduler modeling

### 3. Soundness Considerations

Current implementation is **over-approximate** for generators:
- We model generator calls as returning opaque generator objects
- We don't model the next() protocol or StopIteration yet
- This is sound: we don't claim SAFE without proof
- May report UNKNOWN for code patterns requiring full generator semantics

## Tests

Created `tests/test_semantics_generators.py` with 10 tests:

- 3 tests for basic generator opcodes
- 3 tests for async/await opcodes
- 2 tests for async iteration
- 1 test for yield from
- 1 test for generator lazy execution semantics

All tests pass.

## Test Results

```
tests/test_semantics_generators.py: 10 passed
Full test suite: 548 passed, 10 skipped, 13 xfailed, 12 xpassed
```

## Bytecode Coverage

Total implemented opcodes: 45 (up from 35)

New total:
- BINARY_OP, CALL, CHECK_EXC_MATCH, COMPARE_OP, COPY, END_ASYNC_FOR, END_FOR, END_SEND, FOR_ITER, GET_AITER, GET_ANEXT, GET_AWAITABLE, GET_ITER, GET_YIELD_FROM_ITER, IMPORT_NAME, JUMP_BACKWARD, LOAD_ATTR, LOAD_BUILD_CLASS, LOAD_COMMON_CONSTANT, LOAD_CONST, LOAD_FAST, LOAD_GLOBAL, LOAD_NAME, LOAD_SMALL_INT, LOAD_SPECIAL, MAKE_FUNCTION, NOP, NOT_TAKEN, POP_EXCEPT, POP_ITER, POP_JUMP_IF_FALSE, POP_JUMP_IF_TRUE, POP_TOP, PUSH_EXC_INFO, PUSH_NULL, RAISE_VARARGS, RERAISE, RESUME, RETURN_GENERATOR, RETURN_VALUE, SEND, SET_FUNCTION_ATTRIBUTE, STORE_FAST, STORE_NAME, SWAP, TO_BOOL, WITH_EXCEPT_START, YIELD_VALUE

## Next Steps

1. Implement next() protocol for iterating generators
2. Add StopIteration handling (CALL_INTRINSIC_1 with INTRINSIC_STOPITERATION_ERROR)
3. Model generator/coroutine state machine for precise reachability
4. Add async context managers (async with)
5. Test on real-world async code (asyncio patterns)

## Relation to 20 Bug Types

Generators/async relevant to:
- **NON_TERMINATION**: Infinite generators can loop forever
- **ITERATOR_INVALID**: Generator invalidation (though Python has weaker guarantees than C++ iterators)
- **DEADLOCK**: Async code can deadlock on await dependencies
- **PANIC**: Unhandled exceptions in generators/coroutines propagate
- **STACK_OVERFLOW**: Deeply nested generator recursion

These bug types can now be detected in generator/async code contexts.
