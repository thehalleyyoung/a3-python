#!/usr/bin/env python3
"""
Kitchensink Differential Round 3: Programs designed to elicit correct results
only *with* kitchensink (proof-suppression & proof-upgrade paths).

Strategy:
 ─────────────────────────────────────────────────────────────────────
 Category A  "PROOF-SUPPRESSION"
   Baseline reports BUG(DIV_ZERO) as false positive, but HSCC'04 / SOS
   barrier proofs prove DIV_ZERO safe  →  kitchensink flips to SAFE.
   Pattern: while <var> > 0:  ...  1/<var>  ...  <var> -= 1
   Extra complexity to trip baseline's path explorer.

 Category B  "PROOF-UPGRADE (UNKNOWN→SAFE)"
   Baseline hits path limit and reports UNKNOWN, but ICE/Houdini prove
   LOOP_SAFETY  →  kitchensink upgrades to SAFE.
   Pattern: many branches before a safe loop, exhausting baseline budget.

 Category C  "BMC/STOCHASTIC BUG-FINDING"
   Real bugs on rare paths that only BMC's BFS or stochastic replay
   discovers.  Baseline's DFS misses them.
   Pattern: bug behind many conditions or specific data values.
 ─────────────────────────────────────────────────────────────────────
"""

import json
import os
import sys
import tempfile
import textwrap
import time
import multiprocessing
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============================================================================
# Test case definitions
# ============================================================================

@dataclass
class TestCase:
    name: str
    category: str        # "A_suppression", "B_upgrade", "C_bugfinding"
    code: str
    description: str
    expect: str          # What we expect kitchensink to do vs baseline


TEST_CASES: List[TestCase] = [

    # ────────────────────────────────────────────────────────────────────
    # Category A: PROOF-SUPPRESSION (safe programs with division in guarded loops)
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="a01_while_countdown_div",
        category="A_suppression",
        description="Countdown loop with division by loop variable; guard x>0 implies x!=0",
        expect="KS: HSCC'04/SOS proves DIV_ZERO safe; baseline may FP on x reaching 0",
        code=textwrap.dedent("""\
            # Safe: x > 0 throughout loop body, division is safe
            x = 10
            total = 0.0
            while x > 0:
                total += 1.0 / x
                x -= 1
            # After loop: x == 0, but no division here
            result = total
        """),
    ),

    TestCase(
        name="a02_nested_div_inner_guard",
        category="A_suppression",
        description="Nested loops; inner loop guards the divisor",
        expect="KS: Barrier proves inner DIV_ZERO safe; baseline loses precision across nesting",
        code=textwrap.dedent("""\
            total = 0.0
            for outer in range(5):
                x = 10
                while x > 0:
                    total += (outer + 1) / x
                    x -= 1
            result = total
        """),
    ),

    TestCase(
        name="a03_harmonic_series",
        category="A_suppression",
        description="Harmonic series computation H_n = sum(1/k for k=1..n)",
        expect="KS: Proves k > 0 inside loop → DIV_ZERO safe; baseline might report FP",
        code=textwrap.dedent("""\
            n = 10
            harmonic = 0.0
            k = n
            while k > 0:
                harmonic += 1.0 / k
                k -= 1
            answer = harmonic
        """),
    ),

    TestCase(
        name="a04_branchy_safe_div",
        category="A_suppression",
        description="Many branches inside a guard-protected division loop",
        expect="KS: Guard x>0 proves DIV_ZERO safe; branches exhaust baseline paths",
        code=textwrap.dedent("""\
            x = 20
            results = []
            while x > 0:
                if x % 2 == 0:
                    val = 100 / x
                elif x % 3 == 0:
                    val = 200 / x
                elif x % 5 == 0:
                    val = 300 / x
                else:
                    val = 50 / x
                results.append(val)
                x -= 1
            total = sum(results)
        """),
    ),

    TestCase(
        name="a05_while_neq_zero_div",
        category="A_suppression",
        description="Loop guard is x != 0 (also implies nonzero for proof)",
        expect="KS: Guard x!=0 → DIV_ZERO safe; baseline may miss the guard-div link",
        code=textwrap.dedent("""\
            x = 8
            total = 0.0
            while x != 0:
                total += 42.0 / x
                x -= 1
            output = total
        """),
    ),

    TestCase(
        name="a06_double_division_same_guard",
        category="A_suppression",
        description="Two different divisions by the same guarded variable",
        expect="KS: Both divisions proven safe by same barrier; double FP chance for baseline",
        code=textwrap.dedent("""\
            n = 10
            total_a = 0.0
            total_b = 0.0
            while n > 0:
                total_a += 1.0 / n
                total_b += (n * n) / n   # simplifies to n, but still a division
                n -= 1
            result = total_a + total_b
        """),
    ),

    TestCase(
        name="a07_decrement_by_two",
        category="A_suppression",
        description="Loop decrements by 2; guard x > 0 still implies nonzero",
        expect="KS: Affine model captures x -= 2; barrier still holds",
        code=textwrap.dedent("""\
            x = 12
            total = 0.0
            while x > 0:
                total += 100.0 / x
                x -= 2
            answer = total
        """),
    ),

    TestCase(
        name="a08_negative_guard_div",
        category="A_suppression",
        description="Loop guard x < 0 (negative); implies x != 0 for SOS",
        expect="KS: SOS recognizes x < 0 → x != 0; baseline may not handle negative guards",
        code=textwrap.dedent("""\
            x = -1
            total = 0.0
            while x < 0:
                total += 10.0 / x
                x -= 1
                if x < -20:
                    break
            result = total
        """),
    ),

    TestCase(
        name="a09_accumulator_with_side_computation",
        category="A_suppression",
        description="Accumulator loop with unrelated side computation to add paths",
        expect="KS: Barrier ignores side computation; baseline explores it wastefully",
        code=textwrap.dedent("""\
            x = 12
            acc = 0.0
            side = []
            while x > 0:
                acc += 1.0 / x
                # Side computation — lots of branches, safe
                if x > 10:
                    side.append("big")
                elif x > 6:
                    side.append("medium")
                elif x > 3:
                    side.append("small")
                else:
                    side.append("tiny")
                x -= 1
            output = (acc, len(side))
        """),
    ),

    TestCase(
        name="a10_reciprocal_table",
        category="A_suppression",
        description="Build a table of reciprocals 1/1, 1/2, ..., 1/n",
        expect="KS: Guard i > 0 proves safe; baseline may report FP at boundary",
        code=textwrap.dedent("""\
            n = 10
            table = []
            i = n
            while i > 0:
                table.append(1.0 / i)
                i -= 1
            # i is now 0, but no division here
            result = len(table)
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Category B: PROOF-UPGRADE (complex safe programs → UNKNOWN→SAFE)
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="b01_branchy_prefix_safe_loop",
        category="B_upgrade",
        description="8 binary branches (256 paths) before a safe loop; baseline hits 100-path limit",
        expect="KS: ICE/Houdini proves LOOP_SAFETY; baseline UNKNOWN due to path limit",
        code=textwrap.dedent("""\
            # 8 binary branches = 256 paths (exceeds max_paths=100)
            a, b, c, d, e, f, g, h = 10, 20, 30, 40, 50, 60, 70, 80
            x = 0
            if a > 5: x += 1
            else: x += 2
            if b > 10: x += 3
            else: x += 4
            if c > 15: x += 5
            else: x += 6
            if d > 20: x += 7
            else: x += 8
            if e > 25: x += 9
            else: x += 10
            if f > 30: x += 1
            else: x += 2
            if g > 35: x += 3
            else: x += 4
            if h > 40: x += 5
            else: x += 6
            # Safe loop — x is always positive (min: 1+4+6+8+10+2+4+6=41)
            total = 0
            i = 8
            while i > 0:
                total += i
                i -= 1
            result = total + x
        """),
    ),

    TestCase(
        name="b02_loop_with_branchy_body",
        category="B_upgrade",
        description="Loop body has 4 branches × 8 iterations = 4^8 paths (>65k)",
        expect="KS: ICE proves LOOP_SAFETY; baseline hits 100-path limit on loop × branches",
        code=textwrap.dedent("""\
            total = 0
            i = 8
            while i > 0:
                if i % 4 == 0:
                    total += i
                elif i % 4 == 1:
                    total += i * 2
                elif i % 4 == 2:
                    total += i * 3
                else:
                    total += i + 10
                i -= 1
            result = total
        """),
    ),

    TestCase(
        name="b03_data_driven_many_paths",
        category="B_upgrade",
        description="Large data list with per-element branching (16 elements × 4 branches)",
        expect="KS: ICE proves loop safety; baseline exhausts path budget on data-driven branches",
        code=textwrap.dedent("""\
            data = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3]
            total = 0
            for val in data:
                if val > 7:
                    total += val * 10
                elif val > 4:
                    total += val * 5
                elif val > 2:
                    total += val * 2
                else:
                    total += val
            answer = total
        """),
    ),

    TestCase(
        name="b04_nested_for_loops",
        category="B_upgrade",
        description="Nested for loops with conditional — O(n²) paths from iteration × branching",
        expect="KS: ICE proves safety; baseline runs out of paths in nested loop",
        code=textwrap.dedent("""\
            matrix = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]]
            total = 0
            for row in matrix:
                for val in row:
                    if val > 6:
                        total += val
                    else:
                        total -= val
            result = total
        """),
    ),

    TestCase(
        name="b05_deep_while_with_branches",
        category="B_upgrade",
        description="While loop with 3 branches × 15 iterations = 3^15 potential paths",
        expect="KS: ICE proves loop terminates safely; baseline UNKNOWN from path exhaustion",
        code=textwrap.dedent("""\
            n = 15
            acc = 0
            while n > 0:
                if n % 3 == 0:
                    acc += n
                elif n % 3 == 1:
                    acc += n * 2
                else:
                    acc -= n
                n -= 1
            result = acc
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Category C: BMC/STOCHASTIC BUG-FINDING (real bugs, hard for baseline)
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="c01_bug_after_branchy_prefix",
        category="C_bugfinding",
        description="Real div-by-zero after 8 binary branches (256 paths); baseline hits limit before bug",
        expect="KS: BMC's BFS reaches the bug in <256 nodes; baseline DFS exhausts 100-path budget",
        code=textwrap.dedent("""\
            # 8 binary branches = 256 paths, bug at the end
            a, b, c, d = 1, 2, 3, 4
            e, f, g, h = 5, 6, 7, 8
            x = 0
            if a > 0: x += 1
            else: x -= 1
            if b > 1: x += 1
            else: x -= 1
            if c > 2: x += 1
            else: x -= 1
            if d > 3: x += 1
            else: x -= 1
            if e > 4: x += 1
            else: x -= 1
            if f > 5: x += 1
            else: x -= 1
            if g > 6: x += 1
            else: x -= 1
            if h > 7: x += 1
            else: x -= 1
            # On the "all true" path, x=8. On "all false" path, x=-8.
            # But x - 8 = 0 on the "all true" path
            result = 1 / (x - 8)  # BUG on the all-true path
        """),
    ),

    TestCase(
        name="c02_loop_drives_to_zero_then_div",
        category="C_bugfinding",
        description="Loop drives variable to zero, then divides *after* the loop",
        expect="KS: BMC unrolls loop and finds post-loop div-by-zero precisely",
        code=textwrap.dedent("""\
            x = 5
            while x > 0:
                x -= 1
            # x is now 0
            result = 100 / x  # BUG: division by zero AFTER the loop
        """),
    ),

    TestCase(
        name="c03_bug_in_branchy_loop",
        category="C_bugfinding",
        description="Bug inside a loop with many branches; baseline explores wrong branches first",
        expect="KS: BMC BFS finds the bug path; baseline DFS runs out of paths in branches",
        code=textwrap.dedent("""\
            items = [10, 20, 0, 30, 40, 50, 60, 70, 80, 90]
            for item in items:
                if item > 50:
                    pass  # lots of items go here
                elif item > 30:
                    pass
                elif item > 10:
                    pass
                elif item > 0:
                    pass
                else:
                    # item == 0: bug triggered for the one zero
                    result = 100 / item  # BUG: div by zero for item=0
        """),
    ),

    TestCase(
        name="c04_accumulator_overflow_div",
        category="C_bugfinding",
        description="Accumulator-driven: denominator computed from loop, becomes zero",
        expect="KS: BMC tracks accumulator precisely; baseline loses precision",
        code=textwrap.dedent("""\
            denominator = 10
            for i in range(5):
                denominator -= 2
            # denominator = 10 - 5*2 = 0
            result = 1.0 / denominator  # BUG: division by zero
        """),
    ),

    TestCase(
        name="c05_conditional_bug_deep_path",
        category="C_bugfinding",
        description="Bug on a specific conditional path that requires precise state tracking",
        expect="KS: BMC explores breadth-first, reaches the critical path; baseline DFS may miss",
        code=textwrap.dedent("""\
            a = 3
            b = 7
            c = a * b - 21  # c = 0
            d = c + 0       # d = 0
            if a > 0:
                if b > 0:
                    if d >= 0:
                        if d <= 0:
                            # d must be exactly 0 here
                            result = 1 / d  # BUG: division by zero
        """),
    ),

    TestCase(
        name="c06_bug_after_data_processing",
        category="C_bugfinding",
        description="Bug after data processing loop; many data-driven paths before the crash",
        expect="KS: BMC reaches post-processing bug; baseline spends budget on data branches",
        code=textwrap.dedent("""\
            data = [5, 3, 8, 1, 4, 7, 2, 9, 6, 0]
            total = 0
            zeros = 0
            non_zeros = 0
            for val in data:
                if val > 5:
                    total += val * 2
                elif val > 0:
                    total += val
                else:
                    zeros += 1
                non_zeros = len(data) - zeros
            # After processing: zeros=1, non_zeros=9
            # But this division uses (zeros - 1) = 0 as denominator
            avg_of_something = total / (zeros - 1)  # BUG: zeros=1, denominator=0
        """),
    ),

    TestCase(
        name="c07_string_length_driven_bug",
        category="C_bugfinding",
        description="String operations drive a denominator; baseline can't track string lengths",
        expect="KS: BMC concretely evaluates string ops; baseline abstracts away",
        code=textwrap.dedent("""\
            s = "hello"
            s = s.replace("hello", "")
            # s is now ""
            length = len(s)
            result = 42 / length  # BUG: length = 0
        """),
    ),

    TestCase(
        name="c08_two_loops_interact_bug",
        category="C_bugfinding",
        description="Bug emerges from interaction between two counted loops",
        expect="KS: BMC tracks both loop effects; baseline may analyze them independently",
        code=textwrap.dedent("""\
            x = 10
            y = 10
            for i in range(5):
                x -= 1  # x goes 10->9->8->7->6->5
            for j in range(5):
                y -= 3  # y goes 10->7->4->1->-2->-5
            z = x + y  # 5 + (-5) = 0
            result = 100 / z  # BUG: z = 0
        """),
    ),

    TestCase(
        name="c09_fibonacci_mod_reaches_zero",
        category="C_bugfinding",
        description="Fibonacci-like modular sequence reaches zero",
        expect="KS: BMC traces precise values through loop; baseline loses precision",
        code=textwrap.dedent("""\
            a, b = 1, 1
            for _ in range(6):
                a, b = b, (a + b) % 7
            # Sequence: (1,1)->(1,2)->(2,3)->(3,5)->(5,1)->(1,6)->(6,0)
            # b = 0
            result = 100 / b  # BUG: b = 0
        """),
    ),

    TestCase(
        name="c10_dict_key_driven_bug",
        category="C_bugfinding",
        description="Dict operations create a zero denominator; needs precise container tracking",
        expect="KS: BMC tracks dict operations concretely; baseline may abstract away",
        code=textwrap.dedent("""\
            counts = {}
            words = ["a", "b", "a", "c", "b", "a"]
            for w in words:
                counts[w] = counts.get(w, 0) + 1
            # counts = {"a": 3, "b": 2, "c": 1}
            # Missing key "d" defaults to 0
            d_count = counts.get("d", 0)
            avg = 100 / d_count  # BUG: d_count = 0
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Category D: DATA-STRUCTURE BUGS (BMC tracks containers concretely)
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="d01_set_difference_empty",
        category="D_container",
        description="Set difference produces empty set; len() gives 0 denominator",
        expect="KS: BMC concretely tracks set operations; baseline abstracts sets away",
        code=textwrap.dedent("""\
            a = {1, 2, 3}
            b = {1, 2, 3}
            diff = a - b  # empty set
            result = 42 / len(diff)  # BUG: len(diff) = 0
        """),
    ),

    TestCase(
        name="d02_list_filter_empty",
        category="D_container",
        description="List comprehension filter yields empty list; dividing by its length",
        expect="KS: BMC concretely evaluates filter; baseline can't track filtered list size",
        code=textwrap.dedent("""\
            data = [1, 2, 3, 4, 5]
            big = [x for x in data if x > 100]  # empty list
            avg = sum(big) / len(big)  # BUG: len(big) = 0
        """),
    ),

    TestCase(
        name="d03_dict_values_sum_zero",
        category="D_container",
        description="Dict values that sum to zero; baseline can't track aggregated dict values",
        expect="KS: BMC concretely sums dict values; baseline abstracts away",
        code=textwrap.dedent("""\
            scores = {"alice": 5, "bob": -3, "carol": -2}
            total = sum(scores.values())  # 5 + (-3) + (-2) = 0
            normalized = 100 / total  # BUG: total = 0
        """),
    ),

    TestCase(
        name="d04_list_count_zero",
        category="D_container",
        description="list.count() returns 0 for missing element; used as denominator",
        expect="KS: BMC evaluates count concretely; baseline may over-approximate",
        code=textwrap.dedent("""\
            items = [1, 2, 3, 4, 5]
            freq = items.count(99)  # 0: not in list
            proportion = 100 / freq  # BUG: freq = 0
        """),
    ),

    TestCase(
        name="d05_string_find_negative",
        category="D_container",
        description="str.find() returns -1 for missing; offset computation -> -1 -> still buggy",
        expect="KS: BMC tracks string operations concretely; baseline abstracts strings",
        code=textwrap.dedent("""\
            text = "hello world"
            pos = text.find("xyz")  # -1: not found
            # Off-by-one: use pos directly as a count
            count = pos + 1  # 0
            rate = 100 / count  # BUG: count = 0
        """),
    ),

    TestCase(
        name="d06_tuple_index_sum_zero",
        category="D_container",
        description="Tuple element access; specific indices sum to zero",
        expect="KS: BMC tracks tuple indexing concretely",
        code=textwrap.dedent("""\
            data = (10, -10, 5, -5, 3, -3)
            total = data[0] + data[1]  # 10 + (-10) = 0
            result = 1 / total  # BUG: total = 0
        """),
    ),

    TestCase(
        name="d07_nested_dict_missing_key",
        category="D_container",
        description="Nested dict access with default; produces zero",
        expect="KS: BMC tracks nested dict concretely; baseline may not",
        code=textwrap.dedent("""\
            config = {"database": {"timeout": 30, "retries": 0}}
            retries = config["database"]["retries"]  # 0
            per_retry = 100 / retries  # BUG: retries = 0
        """),
    ),

    TestCase(
        name="d08_zip_length_mismatch",
        category="D_container",
        description="Zip produces shorter list; difference in lengths used as denominator",
        expect="KS: BMC tracks zip concretely; baseline abstracts away",
        code=textwrap.dedent("""\
            a = [1, 2, 3, 4, 5]
            b = [10, 20, 30, 40, 50]
            zipped = list(zip(a, b))
            unmatched = len(a) - len(zipped)  # 5 - 5 = 0
            ratio = 100 / unmatched  # BUG: unmatched = 0
        """),
    ),

    TestCase(
        name="d09_enumerate_counter_div",
        category="D_container",
        description="enumerate index at specific position leads to zero denominator",
        expect="KS: BMC tracks enumerate concretely",
        code=textwrap.dedent("""\
            items = ["a", "b", "c"]
            target = "a"
            idx = -1
            for i, item in enumerate(items):
                if item == target:
                    idx = i
                    break
            # idx = 0 (found at first position)
            result = 100 / idx  # BUG: idx = 0
        """),
    ),

    TestCase(
        name="d10_sorted_diff_zero",
        category="D_container",
        description="Sorted list: adjacent elements equal, difference is 0",
        expect="KS: BMC tracks sorting concretely; baseline may abstract sort results",
        code=textwrap.dedent("""\
            data = [3, 1, 4, 1, 5]
            ordered = sorted(data)  # [1, 1, 3, 4, 5]
            gap = ordered[1] - ordered[0]  # 1 - 1 = 0
            result = 100 / gap  # BUG: gap = 0
        """),
    ),

    TestCase(
        name="d11_defaultdict_zero",
        category="D_container",
        description="defaultdict(int) returns 0 for unknown key; used as denominator",
        expect="KS: BMC tracks defaultdict concretely",
        code=textwrap.dedent("""\
            from collections import defaultdict
            counter = defaultdict(int)
            counter["known"] = 5
            val = counter["unknown"]  # 0 (default)
            result = 100 / val  # BUG: val = 0
        """),
    ),

    TestCase(
        name="d12_bool_to_int_sum_zero",
        category="D_container",
        description="Sum of boolean comparisons; all False -> sum 0",
        expect="KS: BMC evaluates comparisons concretely; baseline may not track bool->int",
        code=textwrap.dedent("""\
            values = [1, 2, 3, 4, 5]
            passing = sum(v > 100 for v in values)  # 0: none pass
            avg_pass = 500 / passing  # BUG: passing = 0
        """),
    ),

    TestCase(
        name="d13_str_split_empty",
        category="D_container",
        description="String split produces fewer parts than expected; index->crash or zero",
        expect="KS: BMC tracks split results concretely; baseline can't",
        code=textwrap.dedent("""\
            line = "header:value"
            parts = line.split(":")
            # parts = ["header", "value"], len=2
            # But pretend we expected 3 parts
            extra = len(parts) - 2  # 0
            ratio = 100 / extra  # BUG: extra = 0
        """),
    ),

    TestCase(
        name="d14_min_max_equal",
        category="D_container",
        description="min and max are equal → range is 0; used as denominator",
        expect="KS: BMC evaluates min/max concretely; baseline may over-approximate",
        code=textwrap.dedent("""\
            data = [5, 5, 5, 5]
            data_range = max(data) - min(data)  # 0
            normalized = 100 / data_range  # BUG: data_range = 0
        """),
    ),

    TestCase(
        name="d15_list_index_zero",
        category="D_container",
        description="list.index() returns 0 for first element; used as denominator",
        expect="KS: BMC tracks index concretely; baseline abstracts",
        code=textwrap.dedent("""\
            items = [42, 10, 20, 30]
            pos = items.index(42)  # 0: it's the first element
            rate = 100 / pos  # BUG: pos = 0
        """),
    ),
]


# ============================================================================
# Runner with multiprocessing-based hard timeout
# ============================================================================

def _run_analysis(filepath_str: str, use_kitchensink: bool, result_dict: dict):
    """Worker function run in a child process."""
    try:
        from a3_python.analyzer import Analyzer
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=300)
        t0 = time.time()
        if use_kitchensink:
            r = analyzer.analyze_file_kitchensink(filepath_str)
        else:
            r = analyzer.analyze_file(filepath_str)
        elapsed = time.time() - t0

        # Serialize per_bug_type carefully
        pbt = {}
        if r.per_bug_type:
            for k, v in r.per_bug_type.items():
                if isinstance(v, dict):
                    pbt[k] = {kk: (str(vv) if not isinstance(vv, (str, int, float, bool, type(None))) else vv)
                              for kk, vv in v.items()}
                else:
                    pbt[k] = str(v)

        result_dict["verdict"] = r.verdict
        result_dict["bug_type"] = r.bug_type
        result_dict["message"] = r.message[:200] if r.message else ""
        result_dict["paths"] = r.paths_explored
        result_dict["time_s"] = round(elapsed, 3)
        result_dict["per_bug_type"] = pbt
    except Exception as e:
        result_dict["verdict"] = "ERROR"
        result_dict["bug_type"] = None
        result_dict["message"] = f"{type(e).__name__}: {str(e)[:150]}"
        result_dict["paths"] = 0
        result_dict["time_s"] = 0.0
        result_dict["per_bug_type"] = {}


def run_with_timeout(filepath: str, use_kitchensink: bool, timeout_s: int = 45):
    """Run analysis in a child process with hard timeout."""
    manager = multiprocessing.Manager()
    result_dict = manager.dict()
    p = multiprocessing.Process(
        target=_run_analysis,
        args=(filepath, use_kitchensink, result_dict),
    )
    p.start()
    p.join(timeout=timeout_s)
    if p.is_alive():
        p.kill()
        p.join(timeout=5)
        return {
            "verdict": "TIMEOUT",
            "bug_type": None,
            "message": f"Killed after {timeout_s}s",
            "paths": 0,
            "time_s": float(timeout_s),
            "per_bug_type": {},
        }
    return dict(result_dict)


# ============================================================================
# Main
# ============================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Kitchensink Differential Round 3")
    parser.add_argument("--json", default="results/ks_diff_r3.json")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--filter", type=str, default=None, help="Run only tests matching this substring")
    args = parser.parse_args()

    os.makedirs("results", exist_ok=True)

    cases = TEST_CASES
    if args.filter:
        cases = [tc for tc in cases if args.filter in tc.name]

    print(f"Running {len(cases)} test cases (timeout={args.timeout}s)")
    print("=" * 70)

    results = []
    n_diff = 0

    for idx, tc in enumerate(cases, 1):
        print(f"\n[{idx}/{len(cases)}] {tc.name} ({tc.category})")
        print(f"  {tc.description}")

        # Write code to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
            f.write(tc.code)
            tmpfile = f.name

        try:
            # Run kitchensink
            print(f"  → kitchensink... ", end="", flush=True)
            ks = run_with_timeout(tmpfile, True, args.timeout)
            print(f"{ks['verdict']} ({ks['time_s']:.1f}s)", flush=True)

            # Run baseline
            print(f"  → baseline...    ", end="", flush=True)
            bl = run_with_timeout(tmpfile, False, args.timeout)
            print(f"{bl['verdict']} ({bl['time_s']:.1f}s)", flush=True)

            # Compare
            verdict_diff = ks["verdict"] != bl["verdict"]
            bug_type_diff = ks["bug_type"] != bl["bug_type"]
            pbt_diff = ks["per_bug_type"] != bl["per_bug_type"]
            has_diff = verdict_diff or bug_type_diff or pbt_diff

            if has_diff:
                n_diff += 1

            marker = " *** DIFFERENTIAL ***" if has_diff else ""
            if verdict_diff:
                print(f"  VERDICT: KS={ks['verdict']} vs BL={bl['verdict']}{marker}")
            if bug_type_diff:
                print(f"  BUG_TYPE: KS={ks['bug_type']} vs BL={bl['bug_type']}")
            if pbt_diff:
                ks_proven = [k for k in ks.get("per_bug_type", {}) if not k.startswith("_")]
                print(f"  PER_BUG_TYPE: KS has proofs for: {ks_proven}")

            # Check for suppression
            suppressed = ks.get("per_bug_type", {}).get("_suppressed_bugs")
            if suppressed:
                print(f"  🛡️  PROOF-SUPPRESSION: {list(suppressed.keys()) if isinstance(suppressed, dict) else suppressed}")

            entry = {
                "test_name": tc.name,
                "category": tc.category,
                "description": tc.description,
                "ks_verdict": ks["verdict"],
                "ks_bug_type": ks["bug_type"],
                "ks_time_s": ks["time_s"],
                "ks_paths": ks["paths"],
                "ks_message": ks["message"],
                "ks_per_bug_type": ks["per_bug_type"],
                "bl_verdict": bl["verdict"],
                "bl_bug_type": bl["bug_type"],
                "bl_time_s": bl["time_s"],
                "bl_paths": bl["paths"],
                "bl_message": bl["message"],
                "verdict_diff": verdict_diff,
                "bug_type_diff": bug_type_diff,
                "pbt_diff": pbt_diff,
                "has_differential": has_diff,
            }
            results.append(entry)

        finally:
            os.unlink(tmpfile)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    cat_counts = {}
    for r in results:
        cat = r["category"]
        cat_counts.setdefault(cat, {"total": 0, "diff": 0, "verdict_diff": 0, "suppressed": 0})
        cat_counts[cat]["total"] += 1
        if r["has_differential"]:
            cat_counts[cat]["diff"] += 1
        if r["verdict_diff"]:
            cat_counts[cat]["verdict_diff"] += 1

    for cat, c in sorted(cat_counts.items()):
        print(f"  {cat}: {c['diff']}/{c['total']} differentials ({c['verdict_diff']} verdict-level)")

    # Kitchensink-only-correct cases
    ks_only_correct = []
    for r in results:
        # Kitchensink finds bug that baseline misses
        if r["ks_verdict"] == "BUG" and r["bl_verdict"] in ("UNKNOWN", "SAFE"):
            ks_only_correct.append((r["test_name"], f"KS=BUG, BL={r['bl_verdict']}"))
        # Kitchensink proves safe but baseline says BUG (proof-suppression)
        if r["ks_verdict"] == "SAFE" and r["bl_verdict"] == "BUG":
            ks_only_correct.append((r["test_name"], f"KS=SAFE (proof-suppressed), BL=BUG"))
        # Kitchensink proves safe but baseline says UNKNOWN (proof-upgrade)
        if r["ks_verdict"] == "SAFE" and r["bl_verdict"] == "UNKNOWN":
            ks_only_correct.append((r["test_name"], f"KS=SAFE (proof-upgraded), BL=UNKNOWN"))

    print(f"\nKitchensink-only-correct: {len(ks_only_correct)}")
    for name, reason in ks_only_correct:
        print(f"  • {name}: {reason}")

    total_diff = sum(1 for r in results if r["has_differential"])
    print(f"\nTotal differentials: {total_diff}/{len(results)}")

    # Save JSON
    with open(args.json, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {args.json}")


if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)
    main()
