#!/usr/bin/env python3
"""
Direct comparison of kitchensink vs non-kitchensink analysis
by calling the analyzer APIs directly (bypassing CLI routing).
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from a3_python.analyzer import Analyzer, analyze

TEST_CASES = {
    "loop_div_zero": '''
def countdown_divide(n):
    i = n
    while i > 0:
        i -= 1
    return 100 / i

countdown_divide(10)
''',

    "use_after_close": '''
class Resource:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True
    def read(self):
        if self.closed:
            raise RuntimeError("Read after close")
        return "data"

def use_after_close():
    r = Resource()
    r.close()
    return r.read()

use_after_close()
''',

    "none_return_deref": '''
def find_item(items, key):
    for item in items:
        if item.get("id") == key:
            return item
    return None

def process():
    items = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
    result = find_item(items, 99)
    return result["name"]

process()
''',

    "type_confusion": '''
def process_value(val):
    if isinstance(val, int):
        return val * 2
    elif isinstance(val, str):
        return val.upper()
    return val.strip()

process_value([1, 2, 3])
''',

    "index_oob_loop": '''
def get_pairs(lst):
    pairs = []
    for i in range(len(lst)):
        pairs.append((lst[i], lst[i + 1]))
    return pairs

get_pairs([1, 2, 3])
''',

    "missing_key": '''
def get_config(cfg):
    host = cfg["host"]
    port = cfg["port"]
    timeout = cfg["timeout"]
    return f"{host}:{port} (timeout={timeout})"

get_config({"host": "localhost", "port": 8080})
''',

    "empty_sequence_unpack": '''
def first_and_rest(items):
    first, *rest = items
    return first, rest

first_and_rest([])
''',

    "uninitialized_var": '''
def compute(flag):
    if flag:
        result = 42
    return result

compute(False)
''',

    "dict_mutation_iter": '''
def remove_evens(d):
    for key in d:
        if d[key] % 2 == 0:
            del d[key]

remove_evens({1: 2, 2: 3, 3: 4, 4: 5})
''',

    "string_format_mismatch": '''
def format_record(name, age, score):
    return "Name: %s, Age: %d, Score: %.2f, Rank: %d" % (name, age, score)

format_record("Alice", 30, 95.5)
''',

    "division_aliased": '''
def compute(a, b):
    c = b - a
    d = 100 / c
    return d

compute(5, 5)
''',

    "nested_none_deref": '''
def get_user(db, user_id):
    for u in db:
        if u["id"] == user_id:
            return u
    return None

def get_email(db, user_id):
    user = get_user(db, user_id)
    return user["email"]

get_email([{"id": 1, "email": "a@b.com"}], 999)
''',

    "off_by_one_slice": '''
def last_n(items, n):
    return items[len(items) - n - 1:]

result = last_n([1, 2, 3, 4, 5], 3)
''',

    "assert_reachable": '''
def classify(x):
    if x > 0:
        return "positive"
    elif x < 0:
        return "negative"
    else:
        assert False, "zero not allowed"

classify(0)
''',
}


def run_kitchensink(filepath):
    """Run with kitchensink pipeline."""
    analyzer = Analyzer(verbose=False, enable_concolic=False)
    try:
        result = analyzer.analyze_file_kitchensink(filepath)
        return {
            "verdict": result.verdict,
            "bug_type": getattr(result, "bug_type", None),
            "message": getattr(result, "message", ""),
            "paths_explored": getattr(result, "paths_explored", 0),
            "per_bug_type": {k: v.get("verdict", "") for k, v in (getattr(result, "per_bug_type", {}) or {}).items()},
        }
    except Exception as e:
        return {"verdict": "ERROR", "bug_type": None, "message": str(e)}


def run_basic(filepath):
    """Run without kitchensink (basic analysis only)."""
    try:
        result = analyze(filepath, verbose=False, enable_concolic=False)
        return {
            "verdict": result.verdict,
            "bug_type": getattr(result, "bug_type", None),
            "message": getattr(result, "message", ""),
            "paths_explored": getattr(result, "paths_explored", 0),
        }
    except Exception as e:
        return {"verdict": "ERROR", "bug_type": None, "message": str(e)}


def main():
    print("=" * 80)
    print("KITCHENSINK vs BASIC ANALYSIS — DIRECT API COMPARISON")
    print("=" * 80)

    differentials = []
    results = {}

    for name, code in TEST_CASES.items():
        print(f"\n{'─' * 60}")
        print(f"Test: {name}")

        # Write test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, prefix=f'ks_{name}_') as f:
            f.write(code)
            tmpfile = Path(f.name)

        try:
            # Run kitchensink
            t0 = time.time()
            ks_result = run_kitchensink(tmpfile)
            ks_time = time.time() - t0

            # Run basic
            t0 = time.time()
            basic_result = run_basic(tmpfile)
            basic_time = time.time() - t0

            results[name] = {
                "kitchensink": ks_result,
                "basic": basic_result,
                "ks_time": round(ks_time, 2),
                "basic_time": round(basic_time, 2),
            }

            is_diff = ks_result["verdict"] != basic_result["verdict"]
            marker = " *** DIFFERENTIAL ***" if is_diff else ""

            print(f"  +KS: verdict={ks_result['verdict']}, bug_type={ks_result['bug_type']}, time={ks_time:.2f}s{marker}")
            print(f"  -KS: verdict={basic_result['verdict']}, bug_type={basic_result['bug_type']}, time={basic_time:.2f}s")

            if ks_result.get("per_bug_type"):
                print(f"  +KS proofs: {ks_result['per_bug_type']}")

            if is_diff:
                differentials.append(name)
                print(f"  +KS msg: {ks_result['message']}")
                print(f"  -KS msg: {basic_result['message']}")

        finally:
            os.unlink(tmpfile)

    print(f"\n{'=' * 80}")
    print(f"SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total tests: {len(TEST_CASES)}")
    print(f"Differentials: {len(differentials)}")
    for name in differentials:
        r = results[name]
        print(f"  {name}: +KS={r['kitchensink']['verdict']} ({r['kitchensink']['bug_type']}), -KS={r['basic']['verdict']} ({r['basic']['bug_type']})")

    # Cases where KS finds BUG but basic doesn't
    ks_unique_bugs = [n for n in differentials if results[n]['kitchensink']['verdict'] == 'BUG' and results[n]['basic']['verdict'] != 'BUG']
    print(f"\nKitchensink UNIQUE bug detections: {len(ks_unique_bugs)}")
    for name in ks_unique_bugs:
        r = results[name]
        print(f"  {name}: KS found {r['kitchensink']['bug_type']}")
        print(f"    KS: {r['kitchensink']['message']}")

    # Save
    outpath = Path(__file__).parent.parent / "results" / "kitchensink_direct_diff.json"
    with open(outpath, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nSaved to {outpath}")


if __name__ == "__main__":
    main()
