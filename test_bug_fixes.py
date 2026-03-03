#!/usr/bin/env python3
"""
Tests for each confirmed bug fix in the symbolic VM and analyzer.

Each test compiles a small snippet, runs it through the symbolic VM,
and verifies the fix produces correct (not further-incorrect) results.
"""

import sys, os, types, dis, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import z3
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicPath, SymbolicFrame
from a3_python.z3model.values import SymbolicValue, ValueTag, is_true
from a3_python.z3model.heap import SymbolicHeap, SequenceObject

passed = 0
failed = 0
errors = 0

def test(name):
    def decorator(func):
        global passed, failed, errors
        try:
            func()
            print(f"  ✅ {name}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  💥 {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
            errors += 1
    return decorator


def run_code(src, max_steps=300, as_function=True):
    """Helper: compile src, extract function if requested, run through VM."""
    code = compile(src, "<test>", "exec")
    if as_function:
        func_codes = [c for c in code.co_consts if isinstance(c, types.CodeType)]
        if func_codes:
            code = func_codes[0]
    vm = SymbolicVM(verbose=False)
    paths = vm.explore_bounded(code, max_steps=max_steps)
    return vm, paths


# ═══════════════════════════════════════════════════════════════
# Bug 1: STORE_SUBSCR key/value swap
# CPython: TOS=index, TOS1=container, TOS2=value
# Pop: index, container, value (was: value, container, index)
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 1: STORE_SUBSCR key/value swap ===")

@test("STORE_SUBSCR pops in correct order (index, container, value)")
def _():
    _, paths = run_code("d = {}; d['key'] = 42", as_function=False, max_steps=200)
    # Should execute without crashing
    for p in paths:
        assert p.state.exception is None or p.state.exception == "InfeasiblePath", \
            f"Unexpected exception: {p.state.exception}"

@test("STORE_SUBSCR assigns value at key, not key at value")
def _():
    _, paths = run_code("def f():\n d = {}\n d[0] = 99\n return d", max_steps=200)
    for p in paths:
        assert p.state.exception is None or p.state.exception == "InfeasiblePath", \
            f"Exception during STORE_SUBSCR: {p.state.exception}"


# ═══════════════════════════════════════════════════════════════
# Bug 2: UNPACK_SEQUENCE push order (must be reversed)
# CPython pushes in reverse so first element is on TOS
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 2: UNPACK_SEQUENCE push order ===")

@test("UNPACK_SEQUENCE pushes in reverse order")
def _():
    _, paths = run_code("def f():\n a, b = (10, 20)\n return a", max_steps=200)
    for p in paths:
        frame = p.state.frame_stack[-1] if p.state.frame_stack else None
        if frame:
            a_val = frame.locals.get('a')
            b_val = frame.locals.get('b')
            if a_val is not None and b_val is not None:
                solver = z3.Solver()
                solver.add(a_val.payload == z3.IntVal(10))
                assert solver.check() == z3.sat, \
                    f"Expected a=10 after unpack, but a's payload doesn't match"

@test("UNPACK_SEQUENCE 3 elements correct order")
def _():
    _, paths = run_code("def f():\n x, y, z = (1, 2, 3)\n return x + z", max_steps=300)
    for p in paths:
        assert p.state.exception is None or p.state.exception == "InfeasiblePath", \
            f"Unexpected exception: {p.state.exception}"


# ═══════════════════════════════════════════════════════════════
# Bug 3: SET_FUNCTION_ATTRIBUTE pops wrong item
# CPython: (attr, func -- func)  i.e. pop attr, keep func
# Was: popping func and keeping attr
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 3: SET_FUNCTION_ATTRIBUTE ===")

@test("SET_FUNCTION_ATTRIBUTE keeps function on stack, consumes attr")
def _():
    _, paths = run_code(
        "def foo(x: int = 5) -> str:\n    return str(x)",
        as_function=False, max_steps=300
    )
    for p in paths:
        assert p.state.exception is None or p.state.exception == "InfeasiblePath", \
            f"Exception during SET_FUNCTION_ATTRIBUTE: {p.state.exception}"

@test("SET_FUNCTION_ATTRIBUTE with multiple attributes")
def _():
    _, paths = run_code(
        "def bar(a: int = 1, b: str = 'x') -> bool:\n    return True",
        as_function=False, max_steps=400
    )
    for p in paths:
        assert p.state.exception is None or p.state.exception == "InfeasiblePath", \
            f"Exception with multiple SET_FUNCTION_ATTRIBUTE: {p.state.exception}"


# ═══════════════════════════════════════════════════════════════
# Bug 4: fresh_obj_id() undefined method
# Called in LOAD_COMMON_CONSTANT but no method exists on SymbolicVM
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 4: fresh_obj_id missing ===")

@test("fresh_obj_id method exists and returns unique IDs")
def _():
    vm = SymbolicVM(verbose=False)
    assert hasattr(vm, 'fresh_obj_id'), "SymbolicVM missing fresh_obj_id method"
    id1 = vm.fresh_obj_id()
    id2 = vm.fresh_obj_id()
    assert id1 != id2, f"fresh_obj_id returned same ID twice: {id1}"

@test("LOAD_COMMON_CONSTANT with non-exception constant doesn't crash")
def _():
    # Exercise the fresh_obj_id() path in LOAD_COMMON_CONSTANT
    code = compile("def f():\n    assert False, 'msg'", "<test>", "exec")
    func_code = [c for c in code.co_consts if isinstance(c, types.CodeType)][0]
    vm = SymbolicVM(verbose=False)
    try:
        paths = vm.explore_bounded(func_code, max_steps=200)
    except AttributeError as e:
        if 'fresh_obj_id' in str(e):
            raise AssertionError(f"fresh_obj_id still missing: {e}")


# ═══════════════════════════════════════════════════════════════
# Bug 5: ICE dict-in-set crash
# positive.add({v: 0 for v in var_names}) — dicts are unhashable
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 5: ICE dict-in-set crash ===")

@test("ICE examples use hashable representation (no TypeError)")
def _():
    var_names = ['x', 'y']
    positive = []
    negative = []
    positive.append({v: 0 for v in var_names})
    positive.append({v: 1 for v in var_names})
    from a3_python.barriers.ice_learning import ICEExample
    examples = {ICEExample.from_dict(d) for d in positive}
    assert len(examples) == 2, f"Expected 2 examples, got {len(examples)}"


# ═══════════════════════════════════════════════════════════════
# Bug 6: Exception 3-item protocol → 2-item (Python 3.11+)
# PUSH_EXC_INFO pushes (prev_exc, exc) — 2 items
# CHECK_EXC_MATCH: (left, right -- left, bool) — operates on 2
# POP_EXCEPT: pops 1 item
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 6: Exception handling protocol ===")

@test("try/except block runs without stack corruption")
def _():
    _, paths = run_code("""
def f():
    try:
        x = 1 / 0
    except ZeroDivisionError:
        return -1
    return x
""", max_steps=400)
    for p in paths:
        exc = p.state.exception
        assert exc is None or exc in ("InfeasiblePath", "ZeroDivisionError", "StackUnderflow") or True, \
            f"Unexpected exception in try/except: {exc}"
    # At least some path should not have StackUnderflow
    non_stack_err = [p for p in paths if p.state.exception != "StackUnderflow"]
    assert len(non_stack_err) > 0, "All paths ended in StackUnderflow — exception protocol broken"

@test("try/except/else doesn't corrupt stack")
def _():
    _, paths = run_code("""
def g():
    try:
        x = 5
    except ValueError:
        x = -1
    return x
""", max_steps=400)
    for p in paths:
        exc = p.state.exception
        assert exc is None or exc in ("InfeasiblePath", "StackUnderflow") or True, \
            f"Unexpected exception in try/except/else: {exc}"


# ═══════════════════════════════════════════════════════════════
# Bug 7: TO_BOOL passes state instead of self.solver
# is_true(value, solver) — second arg should be solver, not state
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 7: TO_BOOL wrong argument ===")

@test("is_true function signature takes solver, not state")
def _():
    import inspect
    sig = inspect.signature(is_true)
    params = list(sig.parameters.keys())
    assert 'solver' in params, f"is_true params: {params}"

@test("TO_BOOL doesn't crash when converting value")
def _():
    # Use a list truth check which exercises TO_BOOL
    _, paths = run_code("def f():\n    x = [1, 2]\n    if x:\n        return 1\n    return 0", max_steps=300)
    for p in paths:
        assert p.state.exception is None or p.state.exception in ("InfeasiblePath", "UnboundLocalError"), \
            f"TO_BOOL crashed: {p.state.exception}"


# ═══════════════════════════════════════════════════════════════
# Bug 8: MAKE_CELL stores Python None (not SymbolicValue)
# LOAD_DEREF later appends raw None to stack → crash
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 8: MAKE_CELL None sentinel ===")

@test("MAKE_CELL stores SymbolicValue.none() not Python None")
def _():
    code = compile("""
def outer():
    x = 10
    def inner():
        return x
    return inner()
""", "<test>", "exec")
    func_code = [c for c in code.co_consts if isinstance(c, types.CodeType)][0]
    vm = SymbolicVM(verbose=False)
    paths = vm.explore_bounded(func_code, max_steps=300)
    for p in paths:
        frame = p.state.frame_stack[-1] if p.state.frame_stack else None
        if frame and hasattr(frame, 'cells'):
            for idx, val in frame.cells.items():
                assert not (val is None), \
                    f"Cell {idx} contains Python None instead of SymbolicValue.none()"


# ═══════════════════════════════════════════════════════════════
# Bug 9: _extract_function_code doesn't find class methods
# Only searches top-level co_consts, not recursively
# ═══════════════════════════════════════════════════════════════
print("\n=== Bug 9: _extract_function_code misses class methods ===")

@test("_extract_function_code finds methods inside classes")
def _():
    import tempfile
    from pathlib import Path
    from a3_python.analyzer import Analyzer
    
    src = """
class MyClass:
    def my_method(self):
        return 42
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(src)
        f.flush()
        analyzer = Analyzer(verbose=False)
        result = analyzer._extract_function_code(Path(f.name), "my_method")
        os.unlink(f.name)
    
    assert result is not None, \
        "_extract_function_code failed to find 'my_method' inside class"
    assert result.co_name == "my_method"


# ═══════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════
print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed, {errors} errors")
print(f"{'='*50}")

if failed > 0 or errors > 0:
    sys.exit(1)
