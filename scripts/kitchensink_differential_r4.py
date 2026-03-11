#!/usr/bin/env python3
"""
Kitchensink Differential Round 4: Focused on BMC/stochastic-only-correct cases.

From R1-R3, two patterns produced kitchensink-only-correct results:
  1. BMC concrete dict tracking (c10: dict.get → 0 → div-by-zero)
  2. Stochastic rare-path (R1: multi-branch → path limit → UNKNOWN)

This round creates 20 targeted programs exploiting these patterns:
  - Category E: Dict/container built through loops, deriving zero
  - Category F: Loop-computed values reaching zero (post-loop use)
  - Category G: Rare-path bugs behind many branches (path budget exhaustion)
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


@dataclass
class TestCase:
    name: str
    category: str
    code: str
    description: str


TEST_CASES: List[TestCase] = [

    # ────────────────────────────────────────────────────────────────────
    # Category E: Dict/container built through loops → missing/zero value
    # Pattern: for loop builds state, post-loop query → zero → BUG
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="e01_dict_missing_key_get",
        category="E_dict",
        description="Dict built in loop; queried for absent key with default 0",
        code=textwrap.dedent("""\
            counts = {}
            for ch in "aabbcc":
                counts[ch] = counts.get(ch, 0) + 1
            missing = counts.get("z", 0)
            result = 100 / missing  # BUG: missing = 0
        """),
    ),

    TestCase(
        name="e02_dict_len_minus_expected",
        category="E_dict",
        description="Dict built in loop; len equals expected → difference is 0",
        code=textwrap.dedent("""\
            d = {}
            keys = ["x", "y", "z"]
            for k in keys:
                d[k] = len(k)
            extra = len(d) - 3  # 3 - 3 = 0
            result = 100 / extra  # BUG: extra = 0
        """),
    ),

    TestCase(
        name="e03_dict_pop_count_diff",
        category="E_dict",
        description="Build dict, pop known keys, remaining count is zero",
        code=textwrap.dedent("""\
            d = {}
            for i in range(3):
                d[f"key_{i}"] = i
            for i in range(3):
                d.pop(f"key_{i}")
            remaining = len(d)  # 0
            result = 42 / remaining  # BUG: remaining = 0
        """),
    ),

    TestCase(
        name="e04_counter_dict_absent_word",
        category="E_dict",
        description="Word counter dict; query for word not in corpus",
        code=textwrap.dedent("""\
            corpus = ["the", "cat", "sat", "on", "the", "mat"]
            freq = {}
            for word in corpus:
                freq[word] = freq.get(word, 0) + 1
            dog_freq = freq.get("dog", 0)  # 0: "dog" not in corpus
            ratio = 100 / dog_freq  # BUG: dog_freq = 0
        """),
    ),

    TestCase(
        name="e05_nested_dict_computed_zero",
        category="E_dict",
        description="Nested dict where inner value built via loop is zero",
        code=textwrap.dedent("""\
            groups = {}
            items = [("a", 1), ("a", -1), ("b", 5)]
            for key, val in items:
                groups.setdefault(key, []).append(val)
            a_total = sum(groups.get("a", []))  # 1 + (-1) = 0
            result = 100 / a_total  # BUG: a_total = 0
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Category F: Loop-computed values that reach zero (post-loop use)
    # Pattern: loop accumulates/transforms; result is zero; used as divisor
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="f01_list_append_then_count",
        category="F_computed",
        description="Build list in loop; count of absent element is 0",
        code=textwrap.dedent("""\
            built = []
            for i in range(5):
                built.append(i * 2)
            # built = [0, 2, 4, 6, 8]
            sevens = built.count(7)  # 0: no 7 in list
            result = 100 / sevens  # BUG: sevens = 0
        """),
    ),

    TestCase(
        name="f02_set_intersection_empty",
        category="F_computed",
        description="Two sets from loops with no overlap; intersection length = 0",
        code=textwrap.dedent("""\
            evens = set()
            odds = set()
            for i in range(1, 6):
                if i % 2 == 0:
                    evens.add(i)
                else:
                    odds.add(i)
            overlap = evens & odds  # empty: no number is both even and odd
            result = 100 / len(overlap)  # BUG: len = 0
        """),
    ),

    TestCase(
        name="f03_accumulator_cancels_to_zero",
        category="F_computed",
        description="Accumulator sums positive and negative values that cancel out",
        code=textwrap.dedent("""\
            values = [5, -3, 8, -10]
            total = 0
            for v in values:
                total += v
            # 5 - 3 + 8 - 10 = 0
            avg = 100 / total  # BUG: total = 0
        """),
    ),

    TestCase(
        name="f04_xor_accumulator_zero",
        category="F_computed",
        description="XOR accumulator: a^a = 0 for any a; paired values give 0",
        code=textwrap.dedent("""\
            data = [7, 3, 7, 3]
            xor = 0
            for d in data:
                xor ^= d
            # 7^3^7^3 = 0
            result = 100 / xor  # BUG: xor = 0
        """),
    ),

    TestCase(
        name="f05_product_includes_zero",
        category="F_computed",
        description="Product of list elements including a zero",
        code=textwrap.dedent("""\
            factors = [3, 5, 0, 7]
            product = 1
            for f in factors:
                product *= f
            # 3 * 5 * 0 * 7 = 0
            result = 100 / product  # BUG: product = 0
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Category G: Rare-path bugs behind many branches
    # Pattern: many data-driven branches exhaust baseline's 100-path budget;
    # BMC or stochastic finds the bug on the rare path
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="g01_rare_zero_in_data",
        category="G_rarepath",
        description="Long data list with one zero; many branches per element",
        code=textwrap.dedent("""\
            data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 0]
            for val in data:
                if val > 50:
                    x = val * 2
                elif val > 20:
                    x = val + 10
                elif val > 0:
                    x = val
                else:
                    # Only reached for val=0; last element
                    result = 100 / val  # BUG: val = 0
        """),
    ),

    TestCase(
        name="g02_bug_after_many_iterations",
        category="G_rarepath",
        description="Bug at iteration 10 of a loop with 3 branches (3^10 > 59k paths)",
        code=textwrap.dedent("""\
            values = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
            for v in values:
                if v > 5:
                    pass  # common path
                elif v > 0:
                    pass  # medium path
                else:
                    # v == 0: rare path, only hit once
                    x = 100 / v  # BUG: division by zero
        """),
    ),

    TestCase(
        name="g03_double_loop_rare_combo",
        category="G_rarepath",
        description="Two nested loops; bug only when both indices hit specific values",
        code=textwrap.dedent("""\
            rows = [1, 2, 3, 0]
            cols = [4, 5, 0, 6]
            for r in rows:
                for c in cols:
                    if r > 0 and c > 0:
                        pass  # most combinations safe
                    elif r == 0 and c == 0:
                        # rare combo: both zero
                        result = 100 / (r + c)  # BUG: 0 + 0 = 0
        """),
    ),

    TestCase(
        name="g04_bug_behind_many_safe_elements",
        category="G_rarepath",
        description="Process 12 safe elements then hit one buggy one (4^12 with 4 branches)",
        code=textwrap.dedent("""\
            items = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 0]
            for item in items:
                if item >= 40:
                    x = item // 10
                elif item >= 20:
                    x = item // 5
                elif item > 0:
                    x = item
                else:
                    x = 100 / item  # BUG at item=0
        """),
    ),

    TestCase(
        name="g05_stochastic_multi_container",
        category="G_rarepath",
        description="Process multiple containers; bug in the last one",
        code=textwrap.dedent("""\
            list_a = [1, 2, 3, 4, 5]
            list_b = [10, 20, 30, 40, 50]
            list_c = [7, 0, 3]  # Contains zero
            
            # Process first two lists (many paths)
            total_a = 0
            for a in list_a:
                if a > 3:
                    total_a += a * 2
                else:
                    total_a += a
            
            total_b = 0
            for b in list_b:
                if b > 25:
                    total_b += b
                else:
                    total_b -= b
            
            # Process third list — bug here
            for c in list_c:
                if c > 0:
                    pass
                else:
                    result = 100 / c  # BUG: c=0 in second element
        """),
    ),

    TestCase(
        name="g06_conditional_chain_to_zero",
        category="G_rarepath",
        description="Chain of conditional assignments; one specific path yields zero",
        code=textwrap.dedent("""\
            x = 10
            y = 20
            z = 30
            if x > 5:
                a = x - 10   # a = 0
            else:
                a = x + 1
            if y > 15:
                b = y - 20   # b = 0
            else:
                b = y + 1
            if z > 25:
                c = z - 30   # c = 0
            else:
                c = z + 1
            denominator = a + b + c  # 0 + 0 + 0 = 0
            result = 100 / denominator  # BUG
        """),
    ),

    TestCase(
        name="g07_filter_then_divide_by_count",
        category="G_rarepath",
        description="Filter items in loop; empty result → count 0 → div-by-zero",
        code=textwrap.dedent("""\
            data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            big_count = 0
            small_count = 0
            for val in data:
                if val > 100:
                    big_count += 1
                elif val > 50:
                    pass
                elif val > 25:
                    pass
                else:
                    small_count += 1
            # big_count = 0 (nothing > 100)
            result = 500 / big_count  # BUG: big_count = 0
        """),
    ),

    TestCase(
        name="g08_matrix_trace_zero",
        category="G_rarepath",
        description="Matrix trace computed through loop equals zero; used as divisor",
        code=textwrap.dedent("""\
            matrix = [
                [1, 2, 3],
                [4, -1, 6],
                [7, 8, 0],
            ]
            trace = 0
            for i in range(3):
                row = matrix[i]
                trace += row[i]
            # trace = 1 + (-1) + 0 = 0
            result = 100 / trace  # BUG: trace = 0
        """),
    ),

    TestCase(
        name="g09_running_balance_hits_zero",
        category="G_rarepath",
        description="Bank balance computed through transactions reaches zero",
        code=textwrap.dedent("""\
            balance = 100
            transactions = [-20, -30, 10, -40, -20]
            for tx in transactions:
                if tx > 0:
                    balance += tx
                else:
                    balance += tx  # same operation but different branch
            # balance = 100 - 20 - 30 + 10 - 40 - 20 = 0
            interest = 500 / balance  # BUG: balance = 0
        """),
    ),

    TestCase(
        name="g10_median_diff_zero",
        category="G_rarepath",
        description="Loop finds min/max; difference is zero for uniform data",
        code=textwrap.dedent("""\
            data = [7, 7, 7, 7, 7]
            lo = data[0]
            hi = data[0]
            for val in data:
                if val < lo:
                    lo = val
                if val > hi:
                    hi = val
            span = hi - lo  # 7 - 7 = 0
            normalized = 100 / span  # BUG: span = 0
        """),
    ),
]


# ============================================================================
# Runner
# ============================================================================

def _run_analysis(filepath_str: str, use_kitchensink: bool, result_dict: dict):
    """Worker in child process."""
    try:
        from a3_python.analyzer import Analyzer
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=300)
        t0 = time.time()
        if use_kitchensink:
            r = analyzer.analyze_file_kitchensink(filepath_str)
        else:
            r = analyzer.analyze_file(filepath_str)
        elapsed = time.time() - t0

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


def run_with_timeout(filepath: str, use_kitchensink: bool, timeout_s: int = 30):
    manager = multiprocessing.Manager()
    result_dict = manager.dict()
    p = multiprocessing.Process(target=_run_analysis, args=(filepath, use_kitchensink, result_dict))
    p.start()
    p.join(timeout=timeout_s)
    if p.is_alive():
        p.kill()
        p.join(timeout=5)
        return {"verdict": "TIMEOUT", "bug_type": None, "message": f"Killed after {timeout_s}s",
                "paths": 0, "time_s": float(timeout_s), "per_bug_type": {}}
    return dict(result_dict)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default="results/ks_diff_r4.json")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--filter", type=str, default=None)
    args = parser.parse_args()

    os.makedirs("results", exist_ok=True)
    cases = TEST_CASES
    if args.filter:
        cases = [tc for tc in cases if args.filter in tc.name]

    print(f"Running {len(cases)} test cases (timeout={args.timeout}s)")
    print("=" * 70)

    results = []
    ks_only_correct = []

    for idx, tc in enumerate(cases, 1):
        print(f"\n[{idx}/{len(cases)}] {tc.name} ({tc.category})")
        print(f"  {tc.description}")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
            f.write(tc.code)
            tmpfile = f.name

        try:
            print(f"  → KS... ", end="", flush=True)
            ks = run_with_timeout(tmpfile, True, args.timeout)
            print(f"{ks['verdict']}({ks.get('bug_type','')}) {ks['time_s']:.1f}s", flush=True)

            print(f"  → BL... ", end="", flush=True)
            bl = run_with_timeout(tmpfile, False, args.timeout)
            print(f"{bl['verdict']}({bl.get('bug_type','')}) {bl['time_s']:.1f}s", flush=True)

            verdict_diff = ks["verdict"] != bl["verdict"]
            bug_type_diff = ks["bug_type"] != bl["bug_type"]

            # KS-only-correct: KS finds bug that BL misses OR KS proves safe while BL says BUG
            is_ks_correct = False
            if ks["verdict"] == "BUG" and bl["verdict"] in ("UNKNOWN", "SAFE"):
                is_ks_correct = True
                ks_only_correct.append((tc.name, f"KS=BUG({ks['bug_type']}), BL={bl['verdict']}"))
            elif ks["verdict"] == "SAFE" and bl["verdict"] == "BUG":
                is_ks_correct = True
                ks_only_correct.append((tc.name, f"KS=SAFE(suppressed), BL=BUG({bl['bug_type']})"))
            elif ks["verdict"] == "SAFE" and bl["verdict"] == "UNKNOWN":
                is_ks_correct = True
                ks_only_correct.append((tc.name, f"KS=SAFE(upgraded), BL=UNKNOWN"))

            marker = ""
            if is_ks_correct:
                marker = " ★ KS-ONLY-CORRECT"
            elif verdict_diff:
                marker = " [DIFF]"

            if verdict_diff or bug_type_diff:
                print(f"  → KS={ks['verdict']}({ks['bug_type']}) vs BL={bl['verdict']}({bl['bug_type']}){marker}")

            entry = {
                "test_name": tc.name, "category": tc.category,
                "ks_verdict": ks["verdict"], "ks_bug_type": ks["bug_type"],
                "ks_time_s": ks["time_s"], "ks_paths": ks["paths"],
                "bl_verdict": bl["verdict"], "bl_bug_type": bl["bug_type"],
                "bl_time_s": bl["time_s"], "bl_paths": bl["paths"],
                "verdict_diff": verdict_diff, "bug_type_diff": bug_type_diff,
                "ks_only_correct": is_ks_correct,
            }
            results.append(entry)
        finally:
            os.unlink(tmpfile)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    for cat in sorted(set(r["category"] for r in results)):
        cat_results = [r for r in results if r["category"] == cat]
        ks_wins = sum(1 for r in cat_results if r["ks_only_correct"])
        print(f"  {cat}: {ks_wins}/{len(cat_results)} KS-only-correct")

    print(f"\n★ KS-only-correct: {len(ks_only_correct)}/{len(results)}")
    for name, reason in ks_only_correct:
        print(f"  • {name}: {reason}")

    # Speed comparison
    ks_times = [r["ks_time_s"] for r in results if r["ks_verdict"] == "BUG"]
    bl_times = [r["bl_time_s"] for r in results if r["bl_verdict"] == "BUG"]
    if ks_times and bl_times:
        print(f"\nBug-finding speed (BUG verdicts only):")
        print(f"  KS avg: {sum(ks_times)/len(ks_times):.2f}s  (n={len(ks_times)})")
        print(f"  BL avg: {sum(bl_times)/len(bl_times):.2f}s  (n={len(bl_times)})")

    with open(args.json, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {args.json}")


if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)
    main()
