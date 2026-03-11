#!/usr/bin/env python3
"""
Kitchensink Differential — ROUND 2: Safe programs requiring proof.

The first round showed that BMC (GOAL 1) intercepts bugs before papers 1-20
get to contribute. The real value of the 20-paper portfolio is proving SAFETY
on programs that the baseline returns UNKNOWN for.

This round focuses on:
  - SAFE programs where baseline says UNKNOWN or gives a false positive
  - Programs requiring invariant discovery, barrier certificates, or
    abstraction refinement to prove safety
  - Composition of multiple paper techniques
"""

import json
import os
import sys
import tempfile
import textwrap
import time
import multiprocessing
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from a3_python.analyzer import Analyzer, AnalysisResult


@dataclass
class TestCase:
    name: str
    papers: List[int]
    goal: int
    code: str
    description: str
    expected_ks_advantage: str


TEST_CASES: List[TestCase] = [
    # ────────────────────────────────────────────────────────────────────
    # Safe loops requiring INVARIANT DISCOVERY to prove (Papers #17,18,10,19)
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="safe_loop_decrement_guard",
        papers=[18, 17],
        goal=3,
        description="Loop with guarded division; invariant n>0 needed to prove safety",
        expected_ks_advantage="Houdini/ICE discovers n>0 invariant, baseline may report false positive",
        code=textwrap.dedent("""\
            # SAFE: division is always guarded by n > 0
            n = 100
            total = 0.0
            while n > 0:
                total = total + 1.0 / n
                n = n - 1
            # After loop: n == 0, total is harmonic(100)
        """),
    ),
    TestCase(
        name="safe_sum_positive_elements",
        papers=[18, 10],
        goal=3,
        description="Count positive elements and divide by count; count is always > 0",
        expected_ks_advantage="IC3/Houdini proves count >= 1 since data[0] > 0",
        code=textwrap.dedent("""\
            # SAFE: data always has at least one positive element
            data = [3, -1, 4, -2, 5]
            count = 0
            total = 0
            for x in data:
                if x > 0:
                    count = count + 1
                    total = total + x
            # count >= 1 because data[0] = 3 > 0
            avg = total / count
        """),
    ),
    TestCase(
        name="safe_binary_search_invariant",
        papers=[17, 18, 10],
        goal=3,
        description="Binary search: mid is always in bounds due to lo < hi invariant",
        expected_ks_advantage="Paper #17/18 discover lo<=mid<hi as inductive invariant",
        code=textwrap.dedent("""\
            # SAFE: binary search always accesses valid indices
            arr = [1, 3, 5, 7, 9, 11, 13]
            target = 7
            lo = 0
            hi = 7  # len(arr)
            result = -1
            while lo < hi:
                mid = (lo + hi) // 2
                val = arr[mid]  # SAFE: 0 <= mid < 7
                if val == target:
                    result = mid
                    break
                elif val < target:
                    lo = mid + 1
                else:
                    hi = mid
        """),
    ),
    TestCase(
        name="safe_gcd_euclid",
        papers=[18, 19, 10],
        goal=3,
        description="Euclidean GCD: divisor b is always > 0 (invariant)",
        expected_ks_advantage="Invariant: b > 0 throughout the loop",
        code=textwrap.dedent("""\
            # SAFE: Euclidean GCD, b > 0 is invariant
            a = 48
            b = 18
            while b > 0:
                temp = b
                b = a % b  # b becomes a%b, which is < old b
                a = temp
            # a now holds gcd(48, 18) = 6
            result = 100 / a  # SAFE: a = 6
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Safe numeric programs requiring BARRIER CERTIFICATES (Papers #1,3,6-9)
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="safe_fibonacci_always_positive",
        papers=[1, 6, 9],
        goal=2,
        description="Fibonacci sequence: all values are positive, division is safe",
        expected_ks_advantage="Barrier B(a,b) = min(a,b) proves both always > 0",
        code=textwrap.dedent("""\
            # SAFE: Fibonacci values are always positive
            a = 1
            b = 1
            for i in range(15):
                c = a + b
                a = b
                b = c
            # b is fib(17) = 1597
            result = 1000 / b  # SAFE: b > 0 always
        """),
    ),
    TestCase(
        name="safe_exponential_decay_bounded_away",
        papers=[6, 7, 2],
        goal=4,
        description="Exponential decay but bounded away from zero",
        expected_ks_advantage="SOS-SDP certificate proves x >= 0.01 throughout loop",
        code=textwrap.dedent("""\
            # SAFE: exponential decay but bounded by 1.0
            x = 100.0
            for i in range(10):
                x = x * 0.9 + 1.0  # Converges to 10.0, never reaches 0
            result = 1.0 / x  # SAFE: x converges to ~10
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Safe finite-state requiring ABSTRACTION-REFINEMENT (Papers #12-16)
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="safe_state_machine_predicate_abs",
        papers=[13, 12, 16],
        goal=5,
        description="State machine: only valid states reachable, error branch dead",
        expected_ks_advantage="Predicate abstraction proves state ∈ {0,1,2} is invariant",
        code=textwrap.dedent("""\
            # SAFE: FSM only visits states 0,1,2
            state = 0
            for step in range(30):
                if state == 0:
                    state = 1
                elif state == 1:
                    state = 2
                elif state == 2:
                    state = 0
                # state 3 is never reached
            # After loop: state ∈ {0, 1, 2}
            divisor = state + 1  # At least 1
            result = 100 / divisor  # SAFE
        """),
    ),
    TestCase(
        name="safe_nested_loop_bounds",
        papers=[12, 15, 11],
        goal=5,
        description="Nested loops with index bounds requiring CEGAR/IMC to prove safe",
        expected_ks_advantage="CEGAR proves 0 <= j < 5 is invariant in inner loop",
        code=textwrap.dedent("""\
            # SAFE: nested loops always stay in bounds
            matrix = [[1, 2, 3, 4, 5],
                      [6, 7, 8, 9, 10],
                      [11, 12, 13, 14, 15]]
            total = 0
            for i in range(3):
                for j in range(5):
                    total = total + matrix[i][j]  # SAFE: i<3, j<5
            result = total  # 120
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Safe compositional requiring ASSUME-GUARANTEE (Paper #20)
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="safe_validate_then_divide",
        papers=[20],
        goal=6,
        description="Validator ensures input > 0 before division",
        expected_ks_advantage="Assume-guarantee: validate guarantees x>0, divide assumes it",
        code=textwrap.dedent("""\
            def validate(x):
                '''Guarantees: returns value > 0'''
                if x <= 0:
                    return 1
                return x
            
            def safe_divide(n, d):
                '''Assumes: d > 0'''
                return n / d
            
            raw = -42
            d = validate(raw)
            result = safe_divide(100, d)  # SAFE: d >= 1
        """),
    ),
    TestCase(
        name="safe_multi_module_contracts",
        papers=[20, 13],
        goal=6,
        description="Pipeline: parse->validate->compute, each with contracts",
        expected_ks_advantage="Assume-guarantee verifies each function assuming caller contracts",
        code=textwrap.dedent("""\
            def parse_int(s):
                '''Returns int or 0 on failure.'''
                try:
                    return int(s)
                except (ValueError, TypeError):
                    return 0
            
            def clamp_positive(x):
                '''Guarantees: return >= 1.'''
                if x < 1:
                    return 1
                return x
            
            def compute_ratio(n, d):
                '''Assumes: d >= 1.'''
                return n / d
            
            raw = parse_int("abc")  # returns 0
            safe = clamp_positive(raw)  # returns 1
            result = compute_ratio(42, safe)  # SAFE: safe >= 1
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # Programs with subtle safety needing COMPOSITION of techniques
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="safe_phase_transition_loop",
        papers=[18, 10, 6, 12],
        goal=99,
        description="Loop with phase transition: different invariant in each phase",
        expected_ks_advantage="Needs Houdini+IC3+CEGAR to track phase-dependent invariants",
        code=textwrap.dedent("""\
            # SAFE: Two-phase loop, different invariants per phase
            x = 10
            phase = 0
            for i in range(20):
                if phase == 0:
                    x = x + 1  # Phase 0: x increases
                    if x >= 20:
                        phase = 1
                else:
                    x = x - 1  # Phase 1: x decreases
                    if x <= 5:
                        phase = 0
            # x is always in [5, 20], never 0
            result = 100 / x  # SAFE
        """),
    ),
    TestCase(
        name="safe_accumulator_never_zero",
        papers=[17, 18, 6, 9],
        goal=99,
        description="Accumulator initialized to 1, only multiplied by positives",
        expected_ks_advantage="ICE+Houdini prove acc > 0 is inductive, SOS proves final safety",
        code=textwrap.dedent("""\
            # SAFE: accumulator starts positive and is only multiplied by positives
            acc = 1
            factors = [2, 3, 5, 7, 11]
            for f in factors:
                acc = acc * f  # f > 0 and acc > 0 → acc stays > 0
            # acc = 2*3*5*7*11 = 2310
            result = 10000 / acc  # SAFE
        """),
    ),
    TestCase(
        name="safe_ring_buffer_modular",
        papers=[10, 13, 14],
        goal=99,
        description="Ring buffer: index is always in [0, size) due to modular arithmetic",
        expected_ks_advantage="IC3+Predicate abstraction proves 0 <= idx < 8 is invariant",
        code=textwrap.dedent("""\
            # SAFE: ring buffer with modular index
            buf = [0] * 8
            idx = 0
            for i in range(20):
                buf[idx] = i      # SAFE: idx ∈ [0, 7]
                idx = (idx + 1) % 8
            total = 0
            for v in buf:
                total = total + v
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # FALSE POSITIVE cases: baseline reports BUG incorrectly, KS should not
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="fp_guarded_division_false_alarm",
        papers=[1, 3, 9],
        goal=2,
        description="Division guarded by if-check; baseline may report false positive",
        expected_ks_advantage="Barrier proves guard makes division safe; baseline reports DIV_ZERO FP",
        code=textwrap.dedent("""\
            # SAFE: division is perfectly guarded
            values = [10, 0, 5, 0, 8]
            results = []
            for v in values:
                if v != 0:
                    results.append(100 / v)  # SAFE: guarded by v != 0
                else:
                    results.append(0)
        """),
    ),
    TestCase(
        name="fp_none_check_before_attr",
        papers=[13, 17],
        goal=5,
        description="None check before attribute access; baseline may report NULL_PTR FP",
        expected_ks_advantage="Predicate abstraction proves x is not None on access path",
        code=textwrap.dedent("""\
            # SAFE: None check before attribute access
            class Node:
                def __init__(self, val, nxt=None):
                    self.val = val
                    self.nxt = nxt
            
            head = Node(1, Node(2, Node(3)))
            total = 0
            curr = head
            while curr is not None:
                total = total + curr.val  # SAFE: curr is not None
                curr = curr.nxt
            # total = 6
        """),
    ),
]


def _run_worker(filepath_str, kitchensink, verbose, result_dict):
    """Worker for multiprocessing timeout."""
    filepath = Path(filepath_str)
    analyzer = Analyzer(max_depth=300, max_paths=100, verbose=verbose)
    
    start = time.time()
    try:
        if kitchensink:
            result = analyzer.analyze_file_kitchensink(filepath)
        else:
            result = analyzer.analyze_file(filepath)
        elapsed = time.time() - start
        result_dict['verdict'] = result.verdict
        result_dict['bug_type'] = result.bug_type
        result_dict['message'] = result.message
        result_dict['paths_explored'] = result.paths_explored or 0
        # Serialize per_bug_type safely
        pbt = result.per_bug_type or {}
        safe_pbt = {}
        for k, v in pbt.items():
            if isinstance(v, dict):
                safe_pbt[k] = {k2: str(v2) if k2 == 'proofs' else str(v2) for k2, v2 in v.items()}
            else:
                safe_pbt[k] = str(v)
        result_dict['per_bug_type'] = safe_pbt
        result_dict['elapsed'] = elapsed
    except Exception as e:
        elapsed = time.time() - start
        result_dict['verdict'] = 'ERROR'
        result_dict['bug_type'] = None  
        result_dict['message'] = f"{type(e).__name__}: {e}"
        result_dict['paths_explored'] = 0
        result_dict['per_bug_type'] = {}
        result_dict['elapsed'] = elapsed


def run_analysis(filepath, kitchensink, verbose=False, timeout=45):
    """Run with hard process timeout."""
    manager = multiprocessing.Manager()
    result_dict = manager.dict()
    
    p = multiprocessing.Process(
        target=_run_worker,
        args=(str(filepath), kitchensink, verbose, result_dict)
    )
    p.start()
    p.join(timeout=timeout)
    
    if p.is_alive():
        p.kill()
        p.join(timeout=5)
        return AnalysisResult(verdict="TIMEOUT", message=f"Killed after {timeout}s"), float(timeout)
    
    if 'verdict' not in result_dict:
        return AnalysisResult(verdict="ERROR", message="Worker crashed"), 0.0
    
    elapsed = result_dict.get('elapsed', 0.0)
    result = AnalysisResult(
        verdict=result_dict['verdict'],
        bug_type=result_dict.get('bug_type'),
        message=result_dict.get('message'),
        paths_explored=result_dict.get('paths_explored', 0),
        per_bug_type=dict(result_dict.get('per_bug_type', {})),
    )
    return result, elapsed


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Kitchensink Differential - Round 2 (Safe programs)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", type=str, default="results/ks_diff_r2.json")
    args = parser.parse_args()
    
    tests = TEST_CASES
    
    print(f"Round 2: {len(tests)} SAFE-program differential tests")
    print("=" * 80)
    
    results = []
    diffs = 0
    
    for i, tc in enumerate(tests, 1):
        papers_str = ",".join(f"#{p}" for p in tc.papers)
        print(f"\n[{i}/{len(tests)}] {tc.name} (GOAL {tc.goal}, Papers: {papers_str})")
        print(f"  {tc.description}")
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, prefix=f'ks2_{tc.name}_') as f:
                f.write(tc.code)
                tmppath = Path(f.name)
            
            ks_result, ks_time = run_analysis(tmppath, kitchensink=True, verbose=args.verbose)
            no_ks_result, no_ks_time = run_analysis(tmppath, kitchensink=False, verbose=args.verbose)
            
            tmppath.unlink(missing_ok=True)
            
            ks_pbt = ks_result.per_bug_type or {}
            no_ks_pbt = no_ks_result.per_bug_type or {}
            
            verdict_diff = ks_result.verdict != no_ks_result.verdict
            bug_type_diff = ks_result.bug_type != no_ks_result.bug_type
            ks_only_types = set(ks_pbt.keys()) - set(no_ks_pbt.keys())
            per_bug_type_diff = bool(ks_only_types)
            
            has_diff = verdict_diff or bug_type_diff or per_bug_type_diff
            
            ks_str = f"{ks_result.verdict}"
            if ks_result.bug_type: ks_str += f" ({ks_result.bug_type})"
            ks_str += f" [{ks_time:.1f}s, {ks_result.paths_explored or 0} paths]"
            
            no_ks_str = f"{no_ks_result.verdict}"
            if no_ks_result.bug_type: no_ks_str += f" ({no_ks_result.bug_type})"
            no_ks_str += f" [{no_ks_time:.1f}s, {no_ks_result.paths_explored or 0} paths]"
            
            print(f"  + kitchensink: {ks_str}")
            print(f"  - kitchensink: {no_ks_str}")
            
            if verdict_diff:
                print(f"  ⚡ VERDICT DIFF: {ks_result.verdict} vs {no_ks_result.verdict}")
                diffs += 1
            elif bug_type_diff:
                print(f"  ⚡ BUG TYPE DIFF: {ks_result.bug_type} vs {no_ks_result.bug_type}")
                diffs += 1
            elif per_bug_type_diff:
                print(f"  ⚡ PER-BUG-TYPE DIFF: kitchensink adds: {ks_only_types}")
                diffs += 1
            else:
                print(f"  ≡ Same result")
            
            if ks_pbt:
                for bt, info in ks_pbt.items():
                    if bt not in no_ks_pbt:
                        print(f"  📋 KS-only[{bt}]: {info}")
            
            results.append({
                "test_name": tc.name,
                "papers": tc.papers,
                "goal": tc.goal,
                "ks_verdict": ks_result.verdict,
                "no_ks_verdict": no_ks_result.verdict,
                "verdict_diff": verdict_diff,
                "ks_bug_type": ks_result.bug_type,
                "no_ks_bug_type": no_ks_result.bug_type,
                "bug_type_diff": bug_type_diff,
                "ks_per_bug_type": {k: str(v) for k, v in ks_pbt.items()},
                "no_ks_per_bug_type": {k: str(v) for k, v in no_ks_pbt.items()},
                "per_bug_type_diff": per_bug_type_diff,
                "has_differential": has_diff,
                "ks_time_s": round(ks_time, 3),
                "no_ks_time_s": round(no_ks_time, 3),
                "description": tc.description,
                "expected_ks_advantage": tc.expected_ks_advantage,
            })
            
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    # Summary
    print("\n" + "=" * 80)
    print(f"SUMMARY: {diffs}/{len(results)} tests showed differential")
    
    # Categorize differentials
    verdict_diffs = [r for r in results if r.get('verdict_diff')]
    bt_diffs = [r for r in results if r.get('bug_type_diff')]
    pbt_diffs = [r for r in results if r.get('per_bug_type_diff')]
    
    if verdict_diffs:
        print(f"\n  VERDICT DIFFERENTIALS ({len(verdict_diffs)}):")
        for r in verdict_diffs:
            print(f"    {r['test_name']}: {r['ks_verdict']} vs {r['no_ks_verdict']}")
    
    if bt_diffs:
        print(f"\n  BUG TYPE DIFFERENTIALS ({len(bt_diffs)}):")
        for r in bt_diffs:
            print(f"    {r['test_name']}: {r['ks_bug_type']} vs {r['no_ks_bug_type']}")
    
    if pbt_diffs:
        print(f"\n  PER-BUG-TYPE DIFFERENTIALS ({len(pbt_diffs)}):")
        for r in pbt_diffs:
            ks_only = set(r['ks_per_bug_type'].keys()) - set(r['no_ks_per_bug_type'].keys())
            print(f"    {r['test_name']}: KS adds {ks_only}")
    
    # Save
    with open(args.json, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nJSON saved to {args.json}")


if __name__ == "__main__":
    main()
