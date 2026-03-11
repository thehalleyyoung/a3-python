#!/usr/bin/env python3
"""
Multi-Tool Comparison: A3 vs 8 Popular Python Checkers
=======================================================

Runs nine Python static analysis / bug-finding tools on the same
synthetic benchmark suite and reports classification metrics (TP, TN,
FP, FN, F1, …).

Decision logic per tool
-----------------------
Each tool has its own notion of "issue found".  We map that to a
BUG / SAFE / UNKNOWN verdict:

* **A3**       — uses `Analyzer.analyze_file()`, verdict from result.
* **Bandit**   — `bandit -f json -q`.  Any result → BUG.
* **Pylint**   — `pylint --output-format=json --disable=all --enable=E`.
                 Any error-level message → BUG.
* **Mypy**     — `mypy --no-error-summary`.  Any "error:" → BUG.
* **Ruff**     — `ruff check --output-format=json`.  Any result → BUG.
* **Semgrep**  — `semgrep --config auto --json --quiet`.  Any finding → BUG.
* **Pyflakes** — `pyflakes`.  Any output → BUG.
* **Flake8**   — `flake8 --select=E,F`.  Any issue → BUG.
* **Pyright**  — `pyright --outputjson`.  Any error-severity diagnostic → BUG.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─── Tier classification (matches fair_comparison_a3_esbmc.py) ───────────

TIER_COMMON = {
    "ASSERT_FAIL", "DIV_ZERO", "BOUNDS", "FP_DOMAIN", "INTEGER_OVERFLOW",
    "DOUBLE_FREE", "PANIC", "UNINIT_MEMORY", "NULL_PTR", "STACK_OVERFLOW",
}

# ─── Metrics ─────────────────────────────────────────────────────────────

@dataclass
class Metrics:
    tp: int = 0; tn: int = 0; fp: int = 0; fn: int = 0
    unknown_on_bug: int = 0; unknown_on_safe: int = 0
    errors: int = 0; total: int = 0; total_runtime_sec: float = 0.0

    def update(self, expected: str, predicted: str, runtime: float) -> None:
        self.total += 1
        self.total_runtime_sec += runtime
        if predicted == "ERROR":   self.errors += 1;          return
        if predicted == "UNKNOWN":
            if expected == "BUG":  self.unknown_on_bug += 1
            else:                  self.unknown_on_safe += 1
            return
        if expected == "BUG"  and predicted == "BUG":  self.tp += 1
        elif expected == "SAFE" and predicted == "SAFE": self.tn += 1
        elif expected == "SAFE" and predicted == "BUG":  self.fp += 1
        elif expected == "BUG"  and predicted == "SAFE": self.fn += 1

    @property
    def decided(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall_strict(self) -> float:
        d = self.tp + self.fn + self.unknown_on_bug
        return self.tp / d if d else 0.0

    @property
    def recall_lenient(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1_strict(self) -> float:
        p, r = self.precision, self.recall_strict
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def f1_lenient(self) -> float:
        p, r = self.precision, self.recall_lenient
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def summary(self) -> dict:
        return {
            "tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn,
            "unknown_on_bug": self.unknown_on_bug,
            "unknown_on_safe": self.unknown_on_safe,
            "errors": self.errors, "total": self.total,
            "decided": self.decided,
            "precision": round(self.precision, 4),
            "recall_strict": round(self.recall_strict, 4),
            "recall_lenient": round(self.recall_lenient, 4),
            "f1_strict": round(self.f1_strict, 4),
            "f1_lenient": round(self.f1_lenient, 4),
            "accuracy": round(self.accuracy, 4),
            "avg_runtime_sec": round(self.total_runtime_sec / self.total, 4) if self.total else 0,
            "total_runtime_sec": round(self.total_runtime_sec, 2),
        }


# ─── Tool runners ────────────────────────────────────────────────────────

def run_a3(python_bin: str, file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run A3 → verdict string."""
    start = time.perf_counter()
    snippet = textwrap.dedent(f"""\
        import json, sys
        from pathlib import Path
        from a3_python.analyzer import Analyzer
        p = Path(sys.argv[1])
        try:
            a = Analyzer(verbose=False)
            r = a.analyze_file(p)
            v = getattr(r, 'verdict', None) or 'UNKNOWN'
            bt = getattr(r, 'bug_type', '') or ''
            if v not in ('BUG','SAFE','UNKNOWN'): v='UNKNOWN'
            print(json.dumps({{'verdict':v,'bug_type':bt}}))
        except Exception as e:
            print(json.dumps({{'verdict':'ERROR','error':str(e)[:500]}}))
    """)
    try:
        proc = subprocess.run(
            [python_bin, "-c", snippet, str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        elapsed = time.perf_counter() - start
        if proc.returncode != 0:
            return "ERROR", elapsed
        lines = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
        if not lines:
            return "ERROR", elapsed
        d = json.loads(lines[-1])
        v = d.get("verdict", "UNKNOWN")
        return v if v in ("BUG", "SAFE", "UNKNOWN") else "UNKNOWN", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_bandit(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run Bandit → BUG if any issue, else SAFE."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["bandit", "-f", "json", "-q", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        if proc.stdout:
            d = json.loads(proc.stdout)
            if d.get("results"):
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_pylint(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run Pylint (errors only) → BUG if any error-level message."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["pylint", "--output-format=json", "--disable=all", "--enable=E",
             str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        if proc.stdout and proc.stdout.strip():
            issues = json.loads(proc.stdout)
            if issues:
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_mypy(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run Mypy → BUG if any error reported."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["mypy", "--no-error-summary", "--no-color-output",
             "--ignore-missing-imports", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        output = (proc.stdout or "") + (proc.stderr or "")
        # Mypy returns non-zero if it finds errors
        for line in output.splitlines():
            if ": error:" in line:
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_ruff(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run Ruff → BUG if any issue found."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["ruff", "check", "--output-format=json", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        if proc.stdout and proc.stdout.strip():
            issues = json.loads(proc.stdout)
            if issues:
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_semgrep(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run Semgrep with auto-config → BUG if any finding."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet",
             str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
        elapsed = time.perf_counter() - start
        if proc.stdout and proc.stdout.strip():
            d = json.loads(proc.stdout)
            if d.get("results"):
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_pyflakes(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run Pyflakes → BUG if any diagnostic reported."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["pyflakes", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        output = (proc.stdout or "").strip()
        if output:
            return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_flake8(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run Flake8 (real errors only: F=pyflakes, E9=syntax) → BUG if any."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["flake8", "--select=F,E9", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        output = (proc.stdout or "").strip()
        if output:
            return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_pyright(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """Run Pyright → BUG if any diagnostic with severity 'error'."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["pyright", "--outputjson", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        if proc.stdout and proc.stdout.strip():
            try:
                d = json.loads(proc.stdout)
                diags = d.get("generalDiagnostics", [])
                for diag in diags:
                    if diag.get("severity") == "error":
                        return "BUG", elapsed
            except json.JSONDecodeError:
                pass
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


# Registry of all tool runners
TOOLS = {
    "A3":       lambda fp, t, py: run_a3(py, fp, t),
    "Bandit":   lambda fp, t, py: run_bandit(fp, t),
    "Pylint":   lambda fp, t, py: run_pylint(fp, t),
    "Mypy":     lambda fp, t, py: run_mypy(fp, t),
    "Ruff":     lambda fp, t, py: run_ruff(fp, t),
    "Semgrep":  lambda fp, t, py: run_semgrep(fp, t),
    "Pyflakes": lambda fp, t, py: run_pyflakes(fp, t),
    "Flake8":   lambda fp, t, py: run_flake8(fp, t),
    "Pyright":  lambda fp, t, py: run_pyright(fp, t),
}


# ─── Test case loading ───────────────────────────────────────────────────

def load_synthetic_cases(
    suite_root: Path, manifest_path: Path, tier_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with open(manifest_path) as f:
        manifest = json.load(f)
    cases = []
    for bug_type, files in manifest["bug_types"].items():
        if tier_filter == "common" and bug_type not in TIER_COMMON:
            continue
        for filename, info in files.items():
            file_path = suite_root / bug_type / filename
            if not file_path.exists():
                continue
            cases.append({
                "bug_type": bug_type,
                "file": str(file_path),
                "filename": filename,
                "expected": info["expected"],
                "tier": "common" if bug_type in TIER_COMMON else "extended",
            })
    return sorted(cases, key=lambda c: (c["bug_type"], c["filename"]))


# ─── Main ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Multi-tool Python bug-finding comparison")
    parser.add_argument("--tier", choices=["common", "all"], default="common")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--python", default="/opt/homebrew/bin/python3.11")
    parser.add_argument("--tools", nargs="+", default=list(TOOLS.keys()),
                        help="Tools to run (default: all)")
    parser.add_argument("--json", default="results/multi_tool_comparison.json",
                        help="JSON output path")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    suite_root = Path("tests/synthetic_suite")
    manifest_path = suite_root / "GROUND_TRUTH_MANIFEST.json"
    if not manifest_path.exists():
        print(f"Error: Manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    cases = load_synthetic_cases(suite_root, manifest_path, args.tier)
    if args.limit > 0:
        cases = cases[:args.limit]

    tools_to_run = [t for t in args.tools if t in TOOLS]
    print(f"Loaded {len(cases)} synthetic cases (tier={args.tier})")
    print(f"Running tools: {', '.join(tools_to_run)}")
    print(f"Timeout: {args.timeout}s per tool per case")
    print()

    # Initialize metrics per tool
    metrics: Dict[str, Metrics] = {t: Metrics() for t in tools_to_run}
    details: List[Dict[str, Any]] = []

    for i, case in enumerate(cases):
        fp = Path(case["file"])
        expected = case["expected"]
        row = {
            "bug_type": case["bug_type"],
            "file": case["filename"],
            "expected": expected,
        }
        
        for tool in tools_to_run:
            verdict, runtime = TOOLS[tool](fp, args.timeout, args.python)
            metrics[tool].update(expected, verdict, runtime)
            row[tool] = {"verdict": verdict, "runtime": round(runtime, 3)}

        details.append(row)

        # Progress every 10 cases
        if (i + 1) % 10 == 0 or (i + 1) == len(cases):
            print(f"  [{i+1:3d}/{len(cases)}] {case['bug_type']:20s} "
                  f"{case['filename'][:50]}")

    print()

    # ─── Print results table ─────────────────────────────────────────

    header = f"{'Tool':<10s} {'TP':>4s} {'TN':>4s} {'FP':>4s} {'FN':>4s} " \
             f"{'UNK':>4s} {'Prec':>6s} {'Rec':>6s} {'F1':>6s} " \
             f"{'F1_len':>6s} {'Acc':>6s} {'Time':>7s}"
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for tool in tools_to_run:
        m = metrics[tool]
        s = m.summary()
        unk = m.unknown_on_bug + m.unknown_on_safe
        print(f"{tool:<10s} {s['tp']:4d} {s['tn']:4d} {s['fp']:4d} {s['fn']:4d} "
              f"{unk:4d} {s['precision']:6.3f} {s['recall_strict']:6.3f} "
              f"{s['f1_strict']:6.3f} {s['f1_lenient']:6.3f} "
              f"{s['accuracy']:6.3f} {s['total_runtime_sec']:7.1f}s")
    print("=" * len(header))

    # ─── Per-bug-type breakdown ──────────────────────────────────────

    print("\n\n=== Per-Bug-Type F1 (strict) ===\n")
    bug_types = sorted(set(c["bug_type"] for c in cases))
    
    # Header
    hdr = f"{'BugType':<20s}"
    for tool in tools_to_run:
        hdr += f" {tool:>8s}"
    print(hdr)
    print("-" * len(hdr))

    per_bt_metrics: Dict[str, Dict[str, Metrics]] = {
        bt: {t: Metrics() for t in tools_to_run} for bt in bug_types
    }
    for d in details:
        bt = d["bug_type"]
        for tool in tools_to_run:
            v = d[tool]["verdict"]
            per_bt_metrics[bt][tool].update(d["expected"], v, d[tool]["runtime"])

    for bt in bug_types:
        line = f"{bt:<20s}"
        for tool in tools_to_run:
            m = per_bt_metrics[bt][tool]
            line += f" {m.f1_strict:8.3f}"
        print(line)

    # ─── Disagreement analysis ───────────────────────────────────────

    print("\n\n=== Cases Where A3 ≠ Other Tools ===\n")
    for d in details:
        a3_v = d.get("A3", {}).get("verdict", "?")
        others = {t: d.get(t, {}).get("verdict", "?") for t in tools_to_run if t != "A3"}
        # Cases where A3 is correct but others aren't, or vice versa
        a3_correct = (a3_v == d["expected"]) or (a3_v == "BUG" and d["expected"] == "BUG")
        any_other_correct = any(
            (v == d["expected"]) or (v == "BUG" and d["expected"] == "BUG")
            for v in others.values()
        )
        if a3_v != "UNKNOWN" and (a3_correct != any_other_correct):
            other_str = " ".join(f"{t}={v}" for t, v in others.items() if v != a3_v)
            if other_str:
                marker = "✓A3" if a3_correct else "✗A3"
                print(f"  {marker} {d['expected']:4s} A3={a3_v:7s} {other_str:50s} "
                      f"{d['bug_type']}/{d['file']}")

    # ─── Save JSON ───────────────────────────────────────────────────

    output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "tier": args.tier,
        "tools": tools_to_run,
        "total_cases": len(cases),
        "metrics": {t: metrics[t].summary() for t in tools_to_run},
        "per_bug_type": {
            bt: {t: per_bt_metrics[bt][t].summary() for t in tools_to_run}
            for bt in bug_types
        },
        "details": details,
    }
    out_path = Path(args.json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nJSON results saved to {out_path}")


if __name__ == "__main__":
    main()
