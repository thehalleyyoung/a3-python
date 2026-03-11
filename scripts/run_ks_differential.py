#!/usr/bin/env python3
"""Run individual test files with and without kitchensink,
comparing findings to identify differentials."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

A3_ROOT = Path(__file__).parent.parent

# Test cases: each is a small Python snippet with a known bug
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

    "sql_injection": '''
def build_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query

def handle_request(name):
    return build_query(name)
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

    "recursion_depth": '''
def factorial(n):
    if n == 0:
        return 1
    return n * factorial(n - 1)
factorial(10000)
''',

    "float_comparison": '''
def is_zero(x):
    total = 0.0
    for _ in range(10):
        total += 0.1
    if total == 1.0:
        return True
    return 1.0 / (total - 1.0)
is_zero(0)
''',

    "unvalidated_input_path": '''
import os
def read_user_file(base_dir, filename):
    path = os.path.join(base_dir, filename)
    with open(path) as f:
        return f.read()
read_user_file("/data", "../etc/passwd")
''',

    "empty_sequence_unpack": '''
def first_and_rest(items):
    first, *rest = items
    return first, rest
first_and_rest([])
''',

    "dict_mutation_iter": '''
def remove_evens(d):
    for key in d:
        if d[key] % 2 == 0:
            del d[key]
remove_evens({1: 2, 2: 3, 3: 4, 4: 5})
''',

    "uninitialized_var": '''
def compute(flag):
    if flag:
        result = 42
    return result
compute(False)
''',

    "string_format_mismatch": '''
def format_record(name, age, score):
    return "Name: %s, Age: %d, Score: %.2f, Rank: %d" % (name, age, score)
format_record("Alice", 30, 95.5)
''',
}


def run_a3(filepath, kitchensink=True, verbose=False):
    """Run A3 on a file, return (exit_code, stdout, stderr).
    
    NOTE: Do NOT pass --functions, because that bypasses the kitchensink path.
    The kitchensink pipeline is the module-level analysis path.
    """
    cmd = [
        sys.executable, "-m", "a3_python", "scan",
        str(filepath),
        "--deduplicate",
        "--min-confidence", "0.3",
    ]
    if not kitchensink:
        cmd.append("--no-kitchensink")
    
    env = os.environ.copy()
    env["PYTHONPATH"] = str(A3_ROOT)
    
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(A3_ROOT),
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"


def extract_verdict(stdout):
    """Extract verdict from A3 output."""
    for line in stdout.splitlines():
        line = line.strip()
        if "Verdict:" in line or "verdict:" in line.lower():
            return line
        if line.startswith("BUG:") or line.startswith("SAFE") or line.startswith("UNKNOWN"):
            return line
    # Look for bug count
    for line in stdout.splitlines():
        if "Total bugs found:" in line:
            return line.strip()
    return "NO_VERDICT"


def extract_findings(stdout):
    """Extract bug findings from A3 output."""
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        # Look for bug-type mentions
        if any(kw in line for kw in ["BUG:", "Bug:", "bug_type", "WARNING", "Finding"]):
            findings.append(line)
        elif "\u26a0" in line or "\u2717" in line or "\u00d7" in line:
            findings.append(line)
    return findings


def main():
    print("=" * 80)
    print("KITCHENSINK DIFFERENTIAL TEST")
    print("Finding bugs that A3+KS detects but A3-KS misses")
    print("=" * 80)
    
    differentials = []
    results = {}
    
    for name, code in TEST_CASES.items():
        print(f"\n{'─' * 60}")
        print(f"Test: {name}")
        
        # Write test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, prefix=f'ks_test_{name}_') as f:
            f.write(code)
            tmpfile = f.name
        
        try:
            # Run with kitchensink
            rc_ks, out_ks, err_ks = run_a3(tmpfile, kitchensink=True)
            verdict_ks = extract_verdict(out_ks)
            findings_ks = extract_findings(out_ks)
            
            # Run without kitchensink
            rc_noks, out_noks, err_noks = run_a3(tmpfile, kitchensink=False)
            verdict_noks = extract_verdict(out_noks)
            findings_noks = extract_findings(out_noks)
            
            results[name] = {
                "ks_exit": rc_ks,
                "noks_exit": rc_noks,
                "ks_verdict": verdict_ks,
                "noks_verdict": verdict_noks,
                "ks_findings_count": len(findings_ks),
                "noks_findings_count": len(findings_noks),
                "ks_stdout": out_ks,
                "noks_stdout": out_noks,
            }
            
            is_differential = (rc_ks != rc_noks) or (len(findings_ks) != len(findings_noks))
            marker = " *** DIFFERENTIAL ***" if is_differential else ""
            
            print(f"  +KS: exit={rc_ks}, verdict={verdict_ks}, findings={len(findings_ks)}{marker}")
            print(f"  -KS: exit={rc_noks}, verdict={verdict_noks}, findings={len(findings_noks)}")
            
            if is_differential:
                differentials.append(name)
                # Show details
                print(f"\n  +KS stdout (first 20 lines):")
                for line in out_ks.splitlines()[:20]:
                    print(f"    | {line}")
                print(f"\n  -KS stdout (first 20 lines):")
                for line in out_noks.splitlines()[:20]:
                    print(f"    | {line}")
            
            if rc_ks == -1:
                print(f"  +KS TIMEOUT")
            if rc_noks == -1:
                print(f"  -KS TIMEOUT")
                
        finally:
            os.unlink(tmpfile)
    
    print(f"\n{'=' * 80}")
    print(f"SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total tests: {len(TEST_CASES)}")
    print(f"Differentials (KS finds more): {len(differentials)}")
    for name in differentials:
        r = results[name]
        print(f"  {name}: +KS exit={r['ks_exit']} findings={r['ks_findings_count']}, -KS exit={r['noks_exit']} findings={r['noks_findings_count']}")
    
    # Save results (without full stdout for JSON)
    outpath = A3_ROOT / "results" / "kitchensink_differential.json"
    save_results = {}
    for name, r in results.items():
        save_results[name] = {k: v for k, v in r.items() if k not in ("ks_stdout", "noks_stdout")}
    with open(outpath, 'w') as f:
        json.dump(save_results, f, indent=2)
    print(f"\nResults saved to {outpath}")


if __name__ == "__main__":
    main()
