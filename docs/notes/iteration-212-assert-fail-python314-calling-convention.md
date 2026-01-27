# Iteration 212: ASSERT_FAIL vs PANIC - Python 3.14 Calling Convention Issue

## Problem
tp_01_unconditional_assert_false.py reports PANIC instead of ASSERT_FAIL. The exception type is reported as "UnknownException" instead of "AssertionError".

## Root Cause
Python 3.14 changed the calling convention. For `assert False, "msg"`, the bytecode is:
```
LOAD_COMMON_CONSTANT AssertionError
LOAD_CONST 'msg'
CALL 0
```

Where CALL 0 (argval=0) is **not** using the Python 3.11-3.13 convention with PUSH_NULL. The stack layout is [AssertionError, 'msg'], but our CALL handler was misinterpreting this.

## Debug Findings
1. LOAD_COMMON_CONSTANT correctly sets `_exception_type` attribute on the AssertionError value
2. After LOAD_CONST, stack is [AssertionError_with_attr, 'msg']
3. CALL with nargs=0 was popping 0 args, then popping TOS as callable
4. This got 'msg' (STR) instead of AssertionError (OBJ with _exception_type)

## Python 3.14 Calling Convention
In Python 3.14 without PUSH_NULL:
- LOAD_COMMON_CONSTANT + CALL may be a special fused operation
- CALL with argval=0 when TOS-1 is from LOAD_COMMON_CONSTANT has different semantics
- Need to investigate PEP or CPython 3.14 changes

## Partial Fix
Added special handling in CALL for exception constructors - check if func_ref has _exception_type attribute and preserve it on the result. But first need to fix the stack interpretation so func_ref is actually the exception type, not the message string.

## Next Steps
1. Research Python 3.14 CALL opcode semantics (check PEP/CPython docs)
2. Fix CALL handler to correctly interpret Python 3.14 stack layout
3. Test with both Python 3.11-3.13 and 3.14 bytecode
4. Remove debug print statements once working

## Status
IN_PROGRESS - identified root cause, need to complete Python 3.14 CALL semantics fix
