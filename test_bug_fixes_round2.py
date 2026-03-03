"""
Tests for round 2 bug fixes in a3_python/z3model/values.py.

Bug fixes:
  1. binary_op_floordiv: Z3 Euclidean div (int) / real div (float) → Python floor division
  2. binary_op_mod: Z3 Euclidean mod → Python floor mod for negative divisors
  3. is_true: Missing float 0.0 as falsy
  4. fresh_bool: Double-wrapping z3.If causing sort error
  5. compare_op_lt/le/gt/ge: Missing float type support
"""

import z3
import pytest
from a3_python.z3model.values import (
    SymbolicValue, ValueTag,
    binary_op_floordiv, binary_op_mod,
    is_true,
    compare_op_lt, compare_op_le, compare_op_gt, compare_op_ge,
)


# ── Helper ──────────────────────────────────────────────────────────────────

def eval_payload(solver, path_cond, value):
    """Evaluate a SymbolicValue's payload under the given path condition."""
    solver.push()
    solver.add(path_cond)
    assert solver.check() == z3.sat
    model = solver.model()
    result = model.eval(value.payload, model_completion=True)
    solver.pop()
    return result


def eval_int(solver, path_cond, value):
    """Evaluate a SymbolicValue as a Python int."""
    r = eval_payload(solver, path_cond, value)
    return r.as_long()


def eval_float(solver, path_cond, value):
    """Evaluate a SymbolicValue as a Python float."""
    r = eval_payload(solver, path_cond, value)
    # r is a Z3 RatNumRef
    return float(r.as_fraction())


# ══════════════════════════════════════════════════════════════════════════════
#  Bug 1: binary_op_floordiv — floor division semantics
# ══════════════════════════════════════════════════════════════════════════════

class TestFloorDiv:
    """Test that binary_op_floordiv matches Python's // for all sign combos."""

    @pytest.mark.parametrize("a,b,expected", [
        (7, 2, 3),       # positive / positive
        (-7, 2, -4),     # negative / positive  (Python floor, NOT -3 trunc)
        (7, -2, -4),     # positive / negative  (Python floor, NOT -3 Euclidean)
        (-7, -2, 3),     # negative / negative  (Python floor, NOT 4 Euclidean)
        (6, 3, 2),       # exact division
        (-6, 3, -2),     # exact negative
        (6, -3, -2),     # exact negative divisor
        (0, 5, 0),       # zero dividend
    ])
    def test_int_floor_div(self, a, b, expected):
        solver = z3.Solver()
        left = SymbolicValue.int(a)
        right = SymbolicValue.int(b)
        result, type_ok, div_zero, none_misuse = binary_op_floordiv(left, right, solver)

        got = eval_int(solver, z3.BoolVal(True), result)
        assert got == expected, f"{a} // {b}: got {got}, expected {expected}"

    @pytest.mark.parametrize("a,b,expected", [
        (7.0, 2.0, 3.0),
        (-7.0, 2.0, -4.0),
        (7.0, -2.0, -4.0),
        (-7.0, -2.0, 3.0),
        (-3.5, 2.0, -2.0),   # fractional
        (3.5, -2.0, -2.0),   # fractional negative divisor
    ])
    def test_float_floor_div(self, a, b, expected):
        solver = z3.Solver()
        left = SymbolicValue.float(a)
        right = SymbolicValue.float(b)
        result, type_ok, div_zero, none_misuse = binary_op_floordiv(left, right, solver)

        got = eval_float(solver, z3.BoolVal(True), result)
        assert got == expected, f"{a} // {b}: got {got}, expected {expected}"


# ══════════════════════════════════════════════════════════════════════════════
#  Bug 2: binary_op_mod — floor modulo semantics
# ══════════════════════════════════════════════════════════════════════════════

class TestFloorMod:
    """Test that binary_op_mod matches Python's % for all sign combos."""

    @pytest.mark.parametrize("a,b,expected", [
        (7, 2, 1),       # positive % positive
        (-7, 2, 1),      # negative % positive  (Python: 1, not -1)
        (7, -2, -1),     # positive % negative  (Python: -1, NOT 1 Euclidean)
        (-7, -2, -1),    # negative % negative  (Python: -1, NOT 1 Euclidean)
        (6, 3, 0),       # exact
        (-6, 3, 0),      # exact negative
        (6, -3, 0),      # exact negative divisor
        (0, 5, 0),       # zero dividend
    ])
    def test_int_floor_mod(self, a, b, expected):
        solver = z3.Solver()
        left = SymbolicValue.int(a)
        right = SymbolicValue.int(b)
        result, type_ok, div_zero, none_misuse = binary_op_mod(left, right, solver)

        got = eval_int(solver, z3.BoolVal(True), result)
        assert got == expected, f"{a} % {b}: got {got}, expected {expected}"


# ══════════════════════════════════════════════════════════════════════════════
#  Bug 3: is_true — float 0.0 should be falsy
# ══════════════════════════════════════════════════════════════════════════════

class TestIsTrueFloat:
    """Test that is_true treats float 0.0 as falsy."""

    def test_float_zero_is_falsy(self):
        solver = z3.Solver()
        val = SymbolicValue.float(0.0)
        cond = is_true(val, solver)
        # cond should be False (0.0 is falsy)
        assert z3.is_false(z3.simplify(cond)), "float 0.0 should be falsy"

    def test_float_nonzero_is_truthy(self):
        solver = z3.Solver()
        val = SymbolicValue.float(1.5)
        cond = is_true(val, solver)
        assert z3.is_true(z3.simplify(cond)), "float 1.5 should be truthy"

    def test_float_negative_zero_is_falsy(self):
        solver = z3.Solver()
        val = SymbolicValue.float(-0.0)
        cond = is_true(val, solver)
        # -0.0 == 0.0 in Python, so also falsy
        assert z3.is_false(z3.simplify(cond)), "float -0.0 should be falsy"

    def test_int_zero_still_falsy(self):
        solver = z3.Solver()
        val = SymbolicValue.int(0)
        cond = is_true(val, solver)
        assert z3.is_false(z3.simplify(cond)), "int 0 should still be falsy"

    def test_none_still_falsy(self):
        solver = z3.Solver()
        val = SymbolicValue.none()
        cond = is_true(val, solver)
        assert z3.is_false(z3.simplify(cond)), "None should still be falsy"


# ══════════════════════════════════════════════════════════════════════════════
#  Bug 4: fresh_bool — should not double-wrap z3.If
# ══════════════════════════════════════════════════════════════════════════════

class TestFreshBool:
    """fresh_bool must not crash with Z3 sort error."""

    def test_fresh_bool_creates_valid_value(self):
        solver = z3.Solver()
        val = SymbolicValue.fresh_bool("test_b", solver)
        # Should not raise Z3 sort error
        assert val.tag == ValueTag.BOOL
        # Payload should be IntSort (0 or 1 encoded)
        assert val.payload.sort() == z3.IntSort()

    def test_fresh_bool_can_be_true_or_false(self):
        solver = z3.Solver()
        val = SymbolicValue.fresh_bool("test_b2", solver)
        # Should be satisfiable as True
        solver.push()
        solver.add(val.payload == z3.IntVal(1))
        assert solver.check() == z3.sat, "fresh_bool should be satisfiable as True"
        solver.pop()
        # Should be satisfiable as False
        solver.push()
        solver.add(val.payload == z3.IntVal(0))
        assert solver.check() == z3.sat, "fresh_bool should be satisfiable as False"
        solver.pop()

    def test_fresh_bool_payload_is_0_or_1(self):
        solver = z3.Solver()
        val = SymbolicValue.fresh_bool("test_b3", solver)
        # The payload should always be 0 or 1
        solver.push()
        solver.add(z3.Not(z3.Or(val.payload == 0, val.payload == 1)))
        assert solver.check() == z3.unsat, "fresh_bool payload must be 0 or 1"
        solver.pop()


# ══════════════════════════════════════════════════════════════════════════════
#  Bug 5: compare_op_lt/le/gt/ge — float type support
# ══════════════════════════════════════════════════════════════════════════════

class TestCompareOpFloat:
    """Test that ordering comparisons accept float operands."""

    def test_lt_float_float_type_ok(self):
        solver = z3.Solver()
        left = SymbolicValue.float(1.5)
        right = SymbolicValue.float(2.5)
        result, type_ok = compare_op_lt(left, right, solver)
        assert z3.is_true(z3.simplify(type_ok)), "float < float should pass type_ok"
        # 1.5 < 2.5 → True
        assert z3.simplify(result.payload) == z3.IntVal(1)

    def test_lt_int_float_type_ok(self):
        solver = z3.Solver()
        left = SymbolicValue.int(1)
        right = SymbolicValue.float(2.5)
        result, type_ok = compare_op_lt(left, right, solver)
        assert z3.is_true(z3.simplify(type_ok)), "int < float should pass type_ok"

    def test_le_float_float(self):
        solver = z3.Solver()
        left = SymbolicValue.float(2.5)
        right = SymbolicValue.float(2.5)
        result, type_ok = compare_op_le(left, right, solver)
        assert z3.is_true(z3.simplify(type_ok)), "float <= float should pass type_ok"
        assert z3.simplify(result.payload) == z3.IntVal(1), "2.5 <= 2.5 should be True"

    def test_gt_float_int(self):
        solver = z3.Solver()
        left = SymbolicValue.float(3.5)
        right = SymbolicValue.int(2)
        result, type_ok = compare_op_gt(left, right, solver)
        assert z3.is_true(z3.simplify(type_ok)), "float > int should pass type_ok"
        assert z3.simplify(result.payload) == z3.IntVal(1), "3.5 > 2 should be True"

    def test_ge_negative_floats(self):
        solver = z3.Solver()
        left = SymbolicValue.float(-1.0)
        right = SymbolicValue.float(0.5)
        result, type_ok = compare_op_ge(left, right, solver)
        assert z3.is_true(z3.simplify(type_ok)), "float >= float should pass type_ok"
        assert z3.simplify(result.payload) == z3.IntVal(0), "-1.0 >= 0.5 should be False"

    def test_int_int_still_works(self):
        """Ensure the existing int-int path is not broken."""
        solver = z3.Solver()
        left = SymbolicValue.int(5)
        right = SymbolicValue.int(3)
        result, type_ok = compare_op_lt(left, right, solver)
        assert z3.is_true(z3.simplify(type_ok))
        assert z3.simplify(result.payload) == z3.IntVal(0), "5 < 3 should be False"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
