#!/usr/bin/env python3
"""
Kitchensink Differential Round 4b: Exploit proven winning patterns.

R4 found 4/20 KS-only-correct. Two winning patterns:
  A) Dict built in loop → query missing key → .get(key, 0) → 0 → div-by-zero
     Baseline says SAFE (doesn't model .get returning default for missing key)
     BMC concretely tracks dict state → finds div-by-zero → BUG
  B) Loop with many branches → accumulator stays 0 → post-loop division
     Baseline runs out of paths → UNKNOWN
     BMC BFS explores post-loop state → BUG

This round creates 20 more programs exploiting these patterns with variations.
"""

import json
import os
import sys
import tempfile
import textwrap
import time
import multiprocessing
from pathlib import Path
from dataclasses import dataclass
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@dataclass
class TestCase:
    name: str
    category: str
    code: str
    description: str


TEST_CASES: List[TestCase] = [

    # ────────────────────────────────────────────────────────────────────
    # Pattern A – dict.get(missing_key, 0) → 0 → division
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="a01_char_freq_missing",
        category="A_dictget",
        description="Char frequency dict; query for char not in string",
        code=textwrap.dedent("""\
            freq = {}
            for c in "hello world":
                freq[c] = freq.get(c, 0) + 1
            z_count = freq.get("z", 0)
            ratio = 10 / z_count  # BUG: z not in string
        """),
    ),

    TestCase(
        name="a02_digit_counter_missing",
        category="A_dictget",
        description="Count digits in string; query for absent digit '9'",
        code=textwrap.dedent("""\
            digits = {}
            for c in "12345678":
                if c.isdigit():
                    digits[c] = digits.get(c, 0) + 1
            nines = digits.get("9", 0)
            result = 100 / nines  # BUG: no '9' in string
        """),
    ),

    TestCase(
        name="a03_pair_counter_missing",
        category="A_dictget",
        description="Count pairs of consecutive chars; query for absent pair",
        code=textwrap.dedent("""\
            text = "aabbc"
            pairs = {}
            for i in range(len(text) - 1):
                p = text[i] + text[i + 1]
                pairs[p] = pairs.get(p, 0) + 1
            zz_count = pairs.get("zz", 0)
            result = 100 / zz_count  # BUG: "zz" never appears
        """),
    ),

    TestCase(
        name="a04_dict_sum_values_zero",
        category="A_dictget",
        description="Dict with positive+negative values; sum via loop is zero",
        code=textwrap.dedent("""\
            data = {"a": 5, "b": -3, "c": -2}
            total = 0
            for key in data:
                total += data[key]
            # 5 + (-3) + (-2) = 0
            result = 100 / total  # BUG: total = 0
        """),
    ),

    TestCase(
        name="a05_status_counter_missing",
        category="A_dictget",
        description="Count status codes; query for absent error code",
        code=textwrap.dedent("""\
            responses = [200, 200, 200, 301, 200, 301]
            counts = {}
            for code in responses:
                counts[code] = counts.get(code, 0) + 1
            errors = counts.get(500, 0)  # 0: no 500 responses
            error_rate = 100 / errors  # BUG: errors = 0
        """),
    ),

    TestCase(
        name="a06_inventory_missing_item",
        category="A_dictget",
        description="Build inventory dict; query for unstocked item",
        code=textwrap.dedent("""\
            shipments = [("apple", 10), ("banana", 5), ("cherry", 8)]
            stock = {}
            for item, qty in shipments:
                stock[item] = stock.get(item, 0) + qty
            mango_stock = stock.get("mango", 0)
            portions = 100 / mango_stock  # BUG: mango_stock = 0
        """),
    ),

    TestCase(
        name="a07_color_frequency_missing",
        category="A_dictget",
        description="Color frequency dict; query for absent color",
        code=textwrap.dedent("""\
            pixels = ["red", "red", "blue", "green", "blue"]
            freq = {}
            for p in pixels:
                freq[p] = freq.get(p, 0) + 1
            yellow_count = freq.get("yellow", 0)
            pct = 100 / yellow_count  # BUG: yellow not in pixels
        """),
    ),

    TestCase(
        name="a08_score_dict_difference_zero",
        category="A_dictget",
        description="Two equal scores in dict; difference is zero",
        code=textwrap.dedent("""\
            scores = {}
            results = [("alice", 75), ("bob", 75)]
            for name, score in results:
                scores[name] = score
            diff = scores.get("alice", 0) - scores.get("bob", 0)
            # 75 - 75 = 0
            normalized = 100 / diff  # BUG: diff = 0
        """),
    ),

    TestCase(
        name="a09_nested_loop_dict",
        category="A_dictget",
        description="Nested loop builds dict; query for absent combo",
        code=textwrap.dedent("""\
            grid = {}
            for r in range(3):
                for c in range(3):
                    grid[(r, c)] = r * c
            val = grid.get((5, 5), 0)
            result = 100 / val  # BUG: (5,5) not in grid, default 0
        """),
    ),

    TestCase(
        name="a10_dict_conditional_build",
        category="A_dictget",
        description="Dict built conditionally; some keys skipped; query for skipped key",
        code=textwrap.dedent("""\
            d = {}
            items = [("x", 10), ("y", 0), ("z", 30)]
            for key, val in items:
                if val > 0:
                    d[key] = val
            # "y" not added (val=0 failed the condition)
            y_val = d.get("y", 0)
            result = 100 / y_val  # BUG: y_val = 0
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Pattern B – Post-loop accumulator stays at 0 / reaches 0
    # (loop has enough iterations+branches to exhaust baseline 100-path budget)
    # ────────────────────────────────────────────────────────────────────

    TestCase(
        name="b01_impossible_filter_count",
        category="B_postloop",
        description="Loop with 8 elements × 3 branches; impossible filter count → 0",
        code=textwrap.dedent("""\
            data = [3, 6, 9, 12, 15, 18, 21, 24]
            big = 0
            for val in data:
                if val > 50:
                    big += 1
                elif val > 25:
                    pass
                else:
                    pass
            result = 100 / big  # BUG: big = 0, nothing > 50
        """),
    ),

    TestCase(
        name="b02_search_miss_counter",
        category="B_postloop",
        description="Search for target in list with branching; not found → 0",
        code=textwrap.dedent("""\
            nums = [2, 4, 6, 8, 10, 12, 14, 16]
            found = 0
            for n in nums:
                if n == 99:
                    found = 1
                elif n > 10:
                    pass
                elif n > 5:
                    pass
                else:
                    pass
            result = 100 / found  # BUG: found = 0, 99 not in list
        """),
    ),

    TestCase(
        name="b03_negative_filter_count",
        category="B_postloop",
        description="Count negatives in all-positive list with branching",
        code=textwrap.dedent("""\
            data = [1, 5, 3, 7, 2, 9, 4, 8, 6, 10]
            neg_count = 0
            for v in data:
                if v < 0:
                    neg_count += 1
                elif v > 5:
                    pass
                else:
                    pass
            result = 100 / neg_count  # BUG: neg_count = 0
        """),
    ),

    TestCase(
        name="b04_even_filter_no_match",
        category="B_postloop",
        description="Count even numbers > 100 in small list with branching",
        code=textwrap.dedent("""\
            numbers = [11, 33, 55, 77, 99, 13, 27, 41]
            even_big = 0
            for n in numbers:
                if n % 2 == 0 and n > 100:
                    even_big += 1
                elif n % 2 == 0:
                    pass
                elif n > 50:
                    pass
                else:
                    pass
            result = 1000 / even_big  # BUG: even_big = 0
        """),
    ),

    TestCase(
        name="b05_running_total_cancels",
        category="B_postloop",
        description="Running total through loop with branches cancels to zero",
        code=textwrap.dedent("""\
            entries = [10, -5, 20, -15, 30, -25, 40, -45]
            total = 0
            for e in entries:
                if e > 0:
                    total += e
                elif e < -20:
                    total += e
                else:
                    total += e
            # total = 10 - 5 + 20 - 15 + 30 - 25 + 40 - 45 = 10
            # Hmm that's 10 not 0. Let me fix:
            # 10 + (-5) + 20 + (-15) + 30 + (-25) + 40 + (-45) = 10
            result = 100 / (total - 10)  # BUG: total=10, 10-10=0
        """),
    ),

    TestCase(
        name="b06_two_loops_both_miss",
        category="B_postloop",
        description="Two sequential loops; combined miss count → 0",
        code=textwrap.dedent("""\
            list_a = [1, 2, 3, 4, 5, 6, 7, 8]
            list_b = [10, 20, 30, 40, 50, 60]
            a_miss = 0
            for v in list_a:
                if v > 100:
                    a_miss += 1
                elif v > 50:
                    pass
                else:
                    pass
            b_miss = 0
            for v in list_b:
                if v > 100:
                    b_miss += 1
                elif v > 50:
                    pass
                else:
                    pass
            total_miss = a_miss + b_miss  # 0 + 0 = 0
            result = 100 / total_miss  # BUG: total_miss = 0
        """),
    ),

    TestCase(
        name="b07_threshold_crossed_never",
        category="B_postloop",
        description="Check if any value crosses threshold; none do → flag stays 0",
        code=textwrap.dedent("""\
            readings = [22, 23, 21, 24, 22, 23, 21, 24, 22, 23]
            alarm_count = 0
            for r in readings:
                if r > 50:
                    alarm_count += 1
                elif r > 30:
                    pass
                elif r > 20:
                    pass
                else:
                    pass
            reaction_time = 100 / alarm_count  # BUG: alarm_count = 0
        """),
    ),

    TestCase(
        name="b08_match_count_zero",
        category="B_postloop",
        description="Pattern matching loop; no pattern found → 0 → division",
        code=textwrap.dedent("""\
            text = "the quick brown fox jumps"
            words = text.split()
            upper_count = 0
            for w in words:
                if w[0].isupper():
                    upper_count += 1
                elif len(w) > 5:
                    pass
                elif len(w) > 3:
                    pass
                else:
                    pass
            avg_len = 100 / upper_count  # BUG: upper_count = 0
        """),
    ),

    TestCase(
        name="b09_accumulate_modular_zero",
        category="B_postloop",
        description="Sum values mod 5 through loop; result is 0",
        code=textwrap.dedent("""\
            data = [5, 10, 15, 20, 25, 30, 35, 40]
            mod_sum = 0
            for d in data:
                if d > 25:
                    mod_sum += d % 5
                elif d > 10:
                    mod_sum += d % 5
                else:
                    mod_sum += d % 5
            # All values are multiples of 5, so d%5 = 0 for all
            result = 100 / mod_sum  # BUG: mod_sum = 0
        """),
    ),

    TestCase(
        name="b10_weighted_sum_zero",
        category="B_postloop",
        description="Weighted sum with alternating +/- weights cancels to zero",
        code=textwrap.dedent("""\
            vals = [1, 2, 3, 4, 5, 6, 7, 8]
            weights = [1, -1, 1, -1, 1, -1, 1, -1]
            weighted = 0
            for i in range(8):
                v = vals[i]
                w = weights[i]
                if w > 0:
                    weighted += v * w
                else:
                    weighted += v * w
            # 1-2+3-4+5-6+7-8 = -4
            result = 100 / (weighted + 4)  # BUG: -4+4 = 0
        """),
    ),
]


# ============================================================================
# Runner (same as R4)
# ============================================================================

def _run_analysis(filepath_str: str, use_kitchensink: bool, result_dict: dict):
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
    parser.add_argument("--json", default="results/ks_diff_r4b.json")
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
