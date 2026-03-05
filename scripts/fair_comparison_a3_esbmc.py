#!/usr/bin/env python3.11
"""
Fair Head-to-Head Comparison: A3 vs ESBMC for Python Bug Finding
================================================================

Design Principles for Fairness
-------------------------------
1. **Equal timeouts** — same wall-clock budget for both tools (default: 60 s).
2. **Tiered evaluation** — separate metrics for:
   (a) "Common Ground" bug types both tools can reasonably handle,
   (b) Each tool's extended capabilities,
   (c) Full suite (all 20 categories).
3. **Honest UNKNOWN accounting** — UNKNOWN is tracked separately.
   A tool that honestly says "I don't know" is NOT penalized as a
   false-negative.  We report metrics both WITH and WITHOUT unknowns.
4. **Resource measurement** — wall-clock time tracked per case.
5. **Deterministic ordering** — cases sorted by (bug_type, filename).
6. **Both synthetic and real-world benchmarks** — synthetic suite
   (200 labeled files) and BugsInPy (real-world regression bugs).
7. **No warm-up bias** — optional warm-up run discarded.

Tier Classification
-------------------
ESBMC's Python frontend supports assertions, division-by-zero, bounds,
overflow, floating-point, and (with flags) memory-leak, deadlock,
data-race.  It does NOT support Python-specific concepts like
iterators, send/sync, type confusion, timing channels, info leaks,
or non-termination in the same way.

  Tier 1  (Common Ground — both tools claim coverage):
    ASSERT_FAIL, DIV_ZERO, BOUNDS, FP_DOMAIN, INTEGER_OVERFLOW,
    DOUBLE_FREE, PANIC, UNINIT_MEMORY, NULL_PTR, STACK_OVERFLOW

  Tier 2a (A3-only strength):
    DATA_RACE, DEADLOCK, SEND_SYNC, TIMING_CHANNEL, INFO_LEAK,
    NON_TERMINATION, ITERATOR_INVALID, TYPE_CONFUSION, MEMORY_LEAK,
    USE_AFTER_FREE

  Tier 2b (ESBMC-specific flags):
    Same as Tier 1 but with ESBMC property-specific flags enabled
    (--overflow-check, --memory-leak-check, --deadlock-check, etc.)

Usage:
    python3.11 scripts/fair_comparison_a3_esbmc.py
    python3.11 scripts/fair_comparison_a3_esbmc.py --tier common
    python3.11 scripts/fair_comparison_a3_esbmc.py --limit 10 --verbose
    python3.11 scripts/fair_comparison_a3_esbmc.py --bugsinpy          # real-world only
    python3.11 scripts/fair_comparison_a3_esbmc.py --bugsinpy --synthetic  # both
"""

from __future__ import annotations

import argparse
import json
import os
import site
import subprocess
import sys
import textwrap
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ─── Tier classification ────────────────────────────────────────────────────

TIER_COMMON = {
    "ASSERT_FAIL", "DIV_ZERO", "BOUNDS", "FP_DOMAIN", "INTEGER_OVERFLOW",
    "DOUBLE_FREE", "PANIC", "UNINIT_MEMORY", "NULL_PTR", "STACK_OVERFLOW",
}

TIER_A3_EXTENDED = {
    "DATA_RACE", "DEADLOCK", "SEND_SYNC", "TIMING_CHANNEL", "INFO_LEAK",
    "NON_TERMINATION", "ITERATOR_INVALID", "TYPE_CONFUSION", "MEMORY_LEAK",
    "USE_AFTER_FREE",
}

# ESBMC flags to enable for specific bug types (make it a fair fight)
ESBMC_PROPERTY_FLAGS: Dict[str, List[str]] = {
    "INTEGER_OVERFLOW": ["--overflow-check"],
    "MEMORY_LEAK": ["--memory-leak-check"],
    "DEADLOCK": ["--deadlock-check"],
    "DATA_RACE": ["--data-races-check"],
}


# ─── Metrics ─────────────────────────────────────────────────────────────────

@dataclass
class Metrics:
    """Classification metrics with explicit UNKNOWN tracking."""
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    unknown_on_bug: int = 0     # expected BUG, tool said UNKNOWN
    unknown_on_safe: int = 0    # expected SAFE, tool said UNKNOWN
    errors: int = 0             # tool crashed / parse failure
    total: int = 0
    total_runtime_sec: float = 0.0

    def update(self, expected: str, predicted: str, runtime: float) -> None:
        self.total += 1
        self.total_runtime_sec += runtime

        if predicted == "ERROR":
            self.errors += 1
            return

        if predicted == "UNKNOWN":
            if expected == "BUG":
                self.unknown_on_bug += 1
            else:
                self.unknown_on_safe += 1
            return

        if expected == "BUG" and predicted == "BUG":
            self.tp += 1
        elif expected == "SAFE" and predicted == "SAFE":
            self.tn += 1
        elif expected == "SAFE" and predicted == "BUG":
            self.fp += 1
        elif expected == "BUG" and predicted == "SAFE":
            self.fn += 1

    @property
    def unknown(self) -> int:
        return self.unknown_on_bug + self.unknown_on_safe

    @property
    def decided(self) -> int:
        """Cases where the tool gave a definitive answer."""
        return self.tp + self.tn + self.fp + self.fn

    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    def recall_strict(self) -> float:
        """Recall counting UNKNOWN-on-BUG as missed (harsh)."""
        denom = self.tp + self.fn + self.unknown_on_bug
        return self.tp / denom if denom else 0.0

    def recall_lenient(self) -> float:
        """Recall ignoring UNKNOWNs (only among cases tool attempted)."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    def f1_strict(self) -> float:
        p, r = self.precision(), self.recall_strict()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def f1_lenient(self) -> float:
        p, r = self.precision(), self.recall_lenient()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def decided_accuracy(self) -> float:
        """Accuracy among cases with a definitive answer."""
        return (self.tp + self.tn) / self.decided if self.decided else 0.0

    def unknown_rate(self) -> float:
        return self.unknown / self.total if self.total else 0.0

    def avg_runtime(self) -> float:
        return self.total_runtime_sec / self.total if self.total else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn,
            "unknown_on_bug": self.unknown_on_bug,
            "unknown_on_safe": self.unknown_on_safe,
            "errors": self.errors,
            "total": self.total,
            "decided": self.decided,
            "precision": round(self.precision(), 4),
            "recall_strict": round(self.recall_strict(), 4),
            "recall_lenient": round(self.recall_lenient(), 4),
            "f1_strict": round(self.f1_strict(), 4),
            "f1_lenient": round(self.f1_lenient(), 4),
            "accuracy": round(self.accuracy(), 4),
            "decided_accuracy": round(self.decided_accuracy(), 4),
            "unknown_rate": round(self.unknown_rate(), 4),
            "avg_runtime_sec": round(self.avg_runtime(), 4),
            "total_runtime_sec": round(self.total_runtime_sec, 4),
        }


# ─── Tool runners ───────────────────────────────────────────────────────────

def run_a3(python_bin: str, file_path: Path, timeout_s: int,
           enable_interprocedural: bool = True) -> Tuple[str, Dict[str, Any], float]:
    """
    Run A3 on a single file and return (verdict, detail_dict, runtime_sec).

    Verdicts: "BUG", "SAFE", "UNKNOWN", or "ERROR".
    """
    start = time.perf_counter()
    # Use the analyzer API directly via subprocess to isolate failures
    snippet = textwrap.dedent(f"""\
        import json, sys
        from pathlib import Path
        from a3_python.analyzer import Analyzer

        p = Path(sys.argv[1])
        try:
            a = Analyzer(verbose=False, enable_interprocedural={enable_interprocedural})
            r = a.analyze_file(p)
            verdict = getattr(r, 'verdict', None) or 'UNKNOWN'
            bug_type = getattr(r, 'bug_type', '') or ''

            # Normalize verdict
            if verdict not in ('BUG', 'SAFE', 'UNKNOWN'):
                verdict = 'UNKNOWN'

            print(json.dumps({{'verdict': verdict, 'bug_type': bug_type}}))
        except Exception as e:
            print(json.dumps({{'verdict': 'ERROR', 'error': str(e)[:500]}}))
    """)

    cmd = [python_bin, "-c", snippet, str(file_path)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        elapsed = time.perf_counter() - start
        if proc.returncode != 0:
            stderr_tail = (proc.stderr or "")[-500:]
            return "ERROR", {"error": f"RC={proc.returncode}", "stderr": stderr_tail}, elapsed

        lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
        if not lines:
            return "ERROR", {"error": "no output"}, elapsed

        payload = json.loads(lines[-1])
        verdict = payload.get("verdict", "UNKNOWN")
        if verdict not in ("BUG", "SAFE", "UNKNOWN"):
            verdict = "UNKNOWN"
        return verdict, payload, elapsed

    except subprocess.TimeoutExpired:
        return "UNKNOWN", {"error": "timeout"}, time.perf_counter() - start
    except Exception as exc:
        return "ERROR", {"error": str(exc)[:500]}, time.perf_counter() - start


def run_esbmc(esbmc_bin: Path, python_bin: str, file_path: Path,
              timeout_s: int, bug_type: str = "") -> Tuple[str, Dict[str, Any], float]:
    """
    Run ESBMC on a single file and return (verdict, detail_dict, runtime_sec).

    Automatically enables relevant property flags based on bug_type.
    """
    start = time.perf_counter()
    env = os.environ.copy()
    try:
        env["PYTHONPATH"] = site.getusersitepackages()
    except Exception:
        pass

    cmd = [
        str(esbmc_bin), str(file_path),
        "--python", python_bin,
        "--no-unwinding-assertions",     # don't flag bounded-unwind as failure
        "--unwind", "10",                # reasonable unwind bound
    ]

    # Add bug-type-specific flags for fairness
    extra_flags = ESBMC_PROPERTY_FLAGS.get(bug_type, [])
    cmd.extend(extra_flags)

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, env=env,
        )
        elapsed = time.perf_counter() - start
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        output_tail = output[-3000:]

        if "VERIFICATION FAILED" in output:
            verdict = "BUG"
        elif "VERIFICATION SUCCESSFUL" in output:
            verdict = "SAFE"
        elif proc.returncode != 0:
            # Parse error / unsupported feature / crash
            if any(kw in output for kw in [
                "PARSING ERROR", "Unsupported", "not yet supported",
                "CONVERSION ERROR", "Segmentation fault",
            ]):
                verdict = "UNKNOWN"
            else:
                verdict = "UNKNOWN"
        else:
            verdict = "UNKNOWN"

        return verdict, {
            "return_code": proc.returncode,
            "output_tail": output_tail,
            "extra_flags": extra_flags,
        }, elapsed

    except subprocess.TimeoutExpired:
        return "UNKNOWN", {"error": "timeout", "extra_flags": extra_flags}, time.perf_counter() - start
    except Exception as exc:
        return "ERROR", {"error": str(exc)[:500]}, time.perf_counter() - start


# ─── Synthetic suite loader ─────────────────────────────────────────────────

def load_synthetic_cases(
    suite_root: Path,
    manifest_path: Path,
    tier_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Load labeled test cases from the synthetic suite manifest."""
    with open(manifest_path) as f:
        manifest = json.load(f)

    cases: List[Dict[str, Any]] = []
    for bug_type, files in manifest["bug_types"].items():
        # Apply tier filter
        if tier_filter == "common" and bug_type not in TIER_COMMON:
            continue
        if tier_filter == "extended" and bug_type not in TIER_A3_EXTENDED:
            continue

        for filename, info in files.items():
            file_path = suite_root / bug_type / filename
            if not file_path.exists():
                continue
            cases.append({
                "source": "synthetic",
                "bug_type": bug_type,
                "file": file_path,
                "expected": info["expected"],
                "reason": info.get("reason", ""),
                "tier": "common" if bug_type in TIER_COMMON else "extended",
            })

    return sorted(cases, key=lambda c: (c["bug_type"], c["file"].name))


# ─── BugsInPy loader ────────────────────────────────────────────────────────

def load_bugsinpy_cases(
    bugsinpy_root: Path,
    projects: Optional[List[str]] = None,
    limit: int = 0,
) -> List[Dict[str, Any]]:
    """
    Extract (buggy_file, fixed_file) pairs from BugsInPy patches.

    Each bug yields TWO cases:
      buggy version → expected BUG
      fixed version → expected SAFE
    """
    bugs_dir = bugsinpy_root / "projects"
    if not bugs_dir.exists():
        return []

    available = sorted(d.name for d in bugs_dir.iterdir() if d.is_dir())
    if projects:
        available = [p for p in available if p in projects]

    cases: List[Dict[str, Any]] = []
    for proj in available:
        proj_dir = bugs_dir / proj
        bugs_subdir = proj_dir / "bugs"
        if not bugs_subdir.exists():
            continue

        for bug_dir in sorted(bugs_subdir.iterdir()):
            if not bug_dir.is_dir():
                continue

            # Each BugsInPy bug has a patch file and bug info
            bug_patch = bug_dir / "bug_patch.txt"
            if not bug_patch.exists():
                continue

            # Extract the primary changed Python file from the patch
            py_files = _extract_py_files_from_patch(bug_patch)
            if not py_files:
                continue

            # Try to get buggy and fixed versions
            buggy_file = bug_dir / "buggy_version.py"
            fixed_file = bug_dir / "fixed_version.py"

            # If pre-extracted versions don't exist, try to extract them
            if not buggy_file.exists() or not fixed_file.exists():
                buggy_file, fixed_file = _extract_versions(bug_dir, py_files[0])

            if buggy_file and buggy_file.exists():
                cases.append({
                    "source": "bugsinpy",
                    "bug_type": "REAL_WORLD",
                    "file": buggy_file,
                    "expected": "BUG",
                    "project": proj,
                    "bug_id": bug_dir.name,
                    "tier": "real_world",
                    "reason": f"Known bug from {proj}#{bug_dir.name}",
                })

            if fixed_file and fixed_file.exists():
                cases.append({
                    "source": "bugsinpy",
                    "bug_type": "REAL_WORLD",
                    "file": fixed_file,
                    "expected": "SAFE",
                    "project": proj,
                    "bug_id": bug_dir.name,
                    "tier": "real_world",
                    "reason": f"Fixed version from {proj}#{bug_dir.name}",
                })

            if limit and len(cases) >= limit * 2:
                break
        if limit and len(cases) >= limit * 2:
            break

    return cases


def _extract_py_files_from_patch(patch_path: Path) -> List[str]:
    """Pull Python filenames from a unified diff patch."""
    py_files = []
    try:
        text = patch_path.read_text(errors="replace")
        import re
        for m in re.finditer(r"^---\s+a/(.+\.py)", text, re.MULTILINE):
            py_files.append(m.group(1))
    except Exception:
        pass
    return py_files


def _extract_versions(bug_dir: Path, rel_py: str) -> Tuple[Optional[Path], Optional[Path]]:
    """
    Try to reconstruct buggy/fixed .py files from the patch + project checkout.

    Falls back to None if extraction isn't possible without a full git checkout.
    """
    # Check if there's a pre-extracted directory
    buggy_dir = bug_dir / "buggy"
    fixed_dir = bug_dir / "fixed"

    buggy = buggy_dir / rel_py if buggy_dir.exists() else None
    fixed = fixed_dir / rel_py if fixed_dir.exists() else None

    if buggy and buggy.exists() and fixed and fixed.exists():
        return buggy, fixed

    return None, None


# ─── Report generation ───────────────────────────────────────────────────────

def generate_markdown_report(results: Dict[str, Any], output_path: Path) -> None:
    """Generate a human-readable Markdown comparison report."""
    lines: List[str] = []
    meta = results["metadata"]

    lines.append("# A3 vs ESBMC — Fair Comparison Report")
    lines.append("")
    lines.append(f"**Date**: {meta['timestamp']}")
    lines.append(f"**Total cases**: {meta['total_cases']}")
    lines.append(f"**Timeout**: {meta['timeout_sec']}s (equal for both tools)")
    lines.append(f"**Python**: {meta['python_bin']}")
    lines.append("")

    # Overall summary table
    lines.append("## Overall Results")
    lines.append("")
    _add_comparison_table(lines, results["overall"])

    # Tier breakdown
    if "by_tier" in results:
        lines.append("")
        lines.append("## Results by Tier")
        for tier_name, tier_data in results["by_tier"].items():
            lines.append("")
            lines.append(f"### {tier_name.replace('_', ' ').title()}")
            lines.append("")
            _add_comparison_table(lines, tier_data)

    # Per bug-type breakdown
    if "by_bug_type" in results:
        lines.append("")
        lines.append("## Results by Bug Type")
        lines.append("")
        lines.append("| Bug Type | Tool | TP | TN | FP | FN | UNK | Prec | Recall(strict) | F1(strict) |")
        lines.append("|----------|------|---:|---:|---:|---:|----:|-----:|---------------:|-----------:|")
        for bt in sorted(results["by_bug_type"].keys()):
            bt_data = results["by_bug_type"][bt]
            for tool in ["a3", "esbmc"]:
                m = bt_data[tool]
                lines.append(
                    f"| {bt} | {tool.upper()} | {m['tp']} | {m['tn']} | {m['fp']} | {m['fn']} "
                    f"| {m['unknown_on_bug'] + m['unknown_on_safe']} "
                    f"| {m['precision']:.2f} | {m['recall_strict']:.2f} | {m['f1_strict']:.2f} |"
                )

    # Head-to-head wins
    if "head_to_head" in results:
        h2h = results["head_to_head"]
        lines.append("")
        lines.append("## Head-to-Head Comparison")
        lines.append("")
        lines.append(f"- **A3 wins** (A3 correct, ESBMC wrong/unknown): **{h2h['a3_wins']}**")
        lines.append(f"- **ESBMC wins** (ESBMC correct, A3 wrong/unknown): **{h2h['esbmc_wins']}**")
        lines.append(f"- **Both correct**: **{h2h['both_correct']}**")
        lines.append(f"- **Both wrong/unknown**: **{h2h['both_wrong']}**")

    # Fairness notes
    lines.append("")
    lines.append("## Fairness Notes")
    lines.append("")
    lines.append("1. **Equal timeout** applied to both tools.")
    lines.append("2. **UNKNOWN** verdicts tracked separately — not counted as false negatives in `recall_lenient`.")
    lines.append("3. **Tier 'common'** restricts to bug types both tools claim to support.")
    lines.append("4. **ESBMC property flags** (`--overflow-check`, etc.) enabled when relevant.")
    lines.append("5. **`recall_strict`** counts UNKNOWN-on-BUG as missed; `recall_lenient` does not.")
    lines.append("6. **`decided_accuracy`** = accuracy among cases where the tool gave BUG or SAFE (ignoring UNKNOWN).")
    lines.append("")

    output_path.write_text("\n".join(lines))
    print(f"Markdown report: {output_path}")


def _add_comparison_table(lines: List[str], data: Dict[str, Any]) -> None:
    """Add a two-row comparison table for a3 vs esbmc."""
    lines.append("| Metric | A3 | ESBMC |")
    lines.append("|--------|---:|------:|")

    a = data["a3"]
    e = data["esbmc"]

    for label, key in [
        ("True Positives", "tp"),
        ("True Negatives", "tn"),
        ("False Positives", "fp"),
        ("False Negatives", "fn"),
        ("Unknown (on BUG)", "unknown_on_bug"),
        ("Unknown (on SAFE)", "unknown_on_safe"),
        ("Errors", "errors"),
        ("Decided Cases", "decided"),
        ("Precision", "precision"),
        ("Recall (strict)", "recall_strict"),
        ("Recall (lenient)", "recall_lenient"),
        ("F1 (strict)", "f1_strict"),
        ("F1 (lenient)", "f1_lenient"),
        ("Accuracy", "accuracy"),
        ("Decided Accuracy", "decided_accuracy"),
        ("Unknown Rate", "unknown_rate"),
        ("Avg Runtime (s)", "avg_runtime_sec"),
    ]:
        av = a.get(key, 0)
        ev = e.get(key, 0)

        if isinstance(av, float):
            a_str = f"{av:.4f}"
            e_str = f"{ev:.4f}"
        else:
            a_str = str(av)
            e_str = str(ev)

        lines.append(f"| {label} | {a_str} | {e_str} |")


# ─── Head-to-head analysis ──────────────────────────────────────────────────

def compute_head_to_head(details: List[Dict]) -> Dict[str, Any]:
    """Compute pairwise win/loss/tie for each test case."""
    a3_wins = 0
    esbmc_wins = 0
    both_correct = 0
    both_wrong = 0
    disagreements: List[Dict] = []

    for d in details:
        expected = d["expected"]
        a3_v = d["a3"]["verdict"]
        es_v = d["esbmc"]["verdict"]

        a3_correct = (a3_v == expected)
        es_correct = (es_v == expected)

        if a3_correct and es_correct:
            both_correct += 1
        elif a3_correct and not es_correct:
            a3_wins += 1
            disagreements.append({**d, "winner": "a3"})
        elif es_correct and not a3_correct:
            esbmc_wins += 1
            disagreements.append({**d, "winner": "esbmc"})
        else:
            both_wrong += 1

    return {
        "a3_wins": a3_wins,
        "esbmc_wins": esbmc_wins,
        "both_correct": both_correct,
        "both_wrong": both_wrong,
        "disagreements": disagreements[:50],  # cap for output size
    }


# ─── Main driver ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fair head-to-head comparison: A3 vs ESBMC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Full synthetic suite, common-ground tier only
              python3.11 scripts/fair_comparison_a3_esbmc.py --tier common

              # Quick smoke test (10 cases)
              python3.11 scripts/fair_comparison_a3_esbmc.py --limit 10 --verbose

              # Include BugsInPy real-world bugs
              python3.11 scripts/fair_comparison_a3_esbmc.py --bugsinpy --bugsinpy-projects ansible black keras

              # Both synthetic + real-world
              python3.11 scripts/fair_comparison_a3_esbmc.py --synthetic --bugsinpy
        """),
    )

    # Benchmark selection
    parser.add_argument("--synthetic", action="store_true", default=True,
                        help="Include synthetic suite (default: on)")
    parser.add_argument("--no-synthetic", action="store_true",
                        help="Exclude synthetic suite")
    parser.add_argument("--bugsinpy", action="store_true",
                        help="Include BugsInPy real-world benchmarks")
    parser.add_argument("--bugsinpy-projects", nargs="*",
                        help="Limit BugsInPy to specific projects")
    parser.add_argument("--bugsinpy-limit", type=int, default=0,
                        help="Max BugsInPy bugs to include (0 = all)")

    # Paths
    parser.add_argument("--suite", type=Path,
                        default=Path("tests/synthetic_suite"))
    parser.add_argument("--manifest", type=Path,
                        default=Path("tests/synthetic_suite/GROUND_TRUTH_MANIFEST.json"))
    parser.add_argument("--esbmc", type=Path,
                        default=Path("external_tools/esbmc/build/src/esbmc/esbmc"))
    parser.add_argument("--bugsinpy-root", type=Path,
                        default=Path("BugsInPy"))
    parser.add_argument("--python", dest="python_bin", default="python3.11")

    # Fairness controls
    parser.add_argument("--timeout", type=int, default=60,
                        help="Equal timeout (seconds) for BOTH tools")
    parser.add_argument("--tier", choices=["all", "common", "extended"],
                        default="all",
                        help="Which tier to evaluate (default: all)")

    # Execution controls
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0,
                        help="Only run N cases (0 = all)")
    parser.add_argument("--warmup", type=int, default=0,
                        help="Run N warmup cases (discarded)")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--a3-only", action="store_true",
                        help="Only run A3 (skip ESBMC)")
    parser.add_argument("--esbmc-only", action="store_true",
                        help="Only run ESBMC (skip A3)")

    # Output
    parser.add_argument("--output", type=Path,
                        default=Path("results/fair_comparison.json"))
    parser.add_argument("--report", type=Path,
                        default=Path("results/fair_comparison_report.md"))

    args = parser.parse_args()

    if args.no_synthetic:
        args.synthetic = False

    # ── Build case list ──────────────────────────────────────────────────

    all_cases: List[Dict[str, Any]] = []

    if args.synthetic:
        tier_filter = args.tier if args.tier != "all" else None
        synthetic_cases = load_synthetic_cases(args.suite, args.manifest, tier_filter)
        all_cases.extend(synthetic_cases)
        print(f"Loaded {len(synthetic_cases)} synthetic cases" +
              (f" (tier={args.tier})" if tier_filter else ""))

    if args.bugsinpy:
        bp_cases = load_bugsinpy_cases(
            args.bugsinpy_root, args.bugsinpy_projects, args.bugsinpy_limit)
        all_cases.extend(bp_cases)
        print(f"Loaded {len(bp_cases)} BugsInPy cases")

    if not all_cases:
        print("No cases loaded. Check --suite / --bugsinpy paths.")
        sys.exit(1)

    # Apply start/limit
    if args.start > 0:
        all_cases = all_cases[args.start:]
    if args.limit > 0:
        all_cases = all_cases[:args.limit]

    print(f"Running {len(all_cases)} cases with {args.timeout}s timeout per tool")
    print(f"Tools: {'A3' if not args.esbmc_only else ''}"
          f"{'+ ' if not args.a3_only and not args.esbmc_only else ''}"
          f"{'ESBMC' if not args.a3_only else ''}")
    print()

    # ── Warmup (discarded) ───────────────────────────────────────────────

    if args.warmup > 0 and len(all_cases) > 0:
        warmup_cases = all_cases[:args.warmup]
        print(f"Warming up with {len(warmup_cases)} cases...")
        for wc in warmup_cases:
            if not args.esbmc_only:
                run_a3(args.python_bin, wc["file"], args.timeout)
            if not args.a3_only:
                run_esbmc(args.esbmc, args.python_bin, wc["file"], args.timeout,
                          wc.get("bug_type", ""))

    # ── Run comparison ───────────────────────────────────────────────────

    tools = []
    if not args.esbmc_only:
        tools.append("a3")
    if not args.a3_only:
        tools.append("esbmc")

    overall: Dict[str, Metrics] = {t: Metrics() for t in tools}
    by_tier: Dict[str, Dict[str, Metrics]] = {}
    by_bug_type: Dict[str, Dict[str, Metrics]] = {}
    details: List[Dict[str, Any]] = []

    for idx, case in enumerate(all_cases, 1):
        bug_type = case["bug_type"]
        tier = case.get("tier", "unknown")
        expected = case["expected"]
        fpath = case["file"]

        # Initialize nested dicts
        if tier not in by_tier:
            by_tier[tier] = {t: Metrics() for t in tools}
        if bug_type not in by_bug_type:
            by_bug_type[bug_type] = {t: Metrics() for t in tools}

        entry: Dict[str, Any] = {
            "source": case.get("source", "synthetic"),
            "bug_type": bug_type,
            "file": str(fpath),
            "expected": expected,
            "tier": tier,
        }

        # ── A3 ───────────────────────────────────────────────────────
        if "a3" in tools:
            a3_verdict, a3_detail, a3_sec = run_a3(
                args.python_bin, fpath, args.timeout)

            overall["a3"].update(expected, a3_verdict, a3_sec)
            by_tier[tier]["a3"].update(expected, a3_verdict, a3_sec)
            by_bug_type[bug_type]["a3"].update(expected, a3_verdict, a3_sec)

            entry["a3"] = {
                "verdict": a3_verdict,
                "bug_type": a3_detail.get("bug_type", ""),
                "runtime_sec": round(a3_sec, 4),
                "error": a3_detail.get("error"),
            }
        else:
            entry["a3"] = {"verdict": "SKIPPED"}

        # ── ESBMC ────────────────────────────────────────────────────
        if "esbmc" in tools:
            es_verdict, es_detail, es_sec = run_esbmc(
                args.esbmc, args.python_bin, fpath, args.timeout, bug_type)

            overall["esbmc"].update(expected, es_verdict, es_sec)
            by_tier[tier]["esbmc"].update(expected, es_verdict, es_sec)
            by_bug_type[bug_type]["esbmc"].update(expected, es_verdict, es_sec)

            entry["esbmc"] = {
                "verdict": es_verdict,
                "return_code": es_detail.get("return_code"),
                "runtime_sec": round(es_sec, 4),
                "extra_flags": es_detail.get("extra_flags", []),
                "error": es_detail.get("error"),
            }
        else:
            entry["esbmc"] = {"verdict": "SKIPPED"}

        details.append(entry)

        # Progress
        if args.verbose or idx % 20 == 0:
            a3_v = entry["a3"]["verdict"]
            es_v = entry["esbmc"]["verdict"]
            match = "✓" if (a3_v == expected or es_v == expected) else "✗"
            print(f"  [{idx:3d}/{len(all_cases)}] {match} {bug_type:20s} exp={expected:4s}  "
                  f"A3={a3_v:7s} ESBMC={es_v:7s}  {fpath.name}")

    # ── Compute head-to-head ─────────────────────────────────────────

    h2h = compute_head_to_head(details) if len(tools) == 2 else {}

    # ── Assemble output ──────────────────────────────────────────────

    output = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_cases": len(all_cases),
            "timeout_sec": args.timeout,
            "python_bin": args.python_bin,
            "esbmc_bin": str(args.esbmc),
            "tier_filter": args.tier,
            "synthetic_included": args.synthetic,
            "bugsinpy_included": args.bugsinpy,
        },
        "overall": {t: overall[t].to_dict() for t in tools},
        "by_tier": {
            tier: {t: by_tier[tier][t].to_dict() for t in tools}
            for tier in by_tier
        },
        "by_bug_type": {
            bt: {t: by_bug_type[bt][t].to_dict() for t in tools}
            for bt in sorted(by_bug_type)
        },
        "head_to_head": h2h,
        "details": details,
    }

    # ── Save ─────────────────────────────────────────────────────────

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nJSON results: {args.output}")

    generate_markdown_report(output, args.report)

    # ── Print summary ────────────────────────────────────────────────

    print("\n" + "=" * 78)
    print(f"OVERALL SUMMARY (equal {args.timeout}s timeout)")
    print("=" * 78)
    for t in tools:
        m = output["overall"][t]
        print(f"\n  {t.upper()}")
        print(f"    Cases decided:     {m['decided']}/{m['total']}  "
              f"(unknown rate: {m['unknown_rate']:.1%})")
        print(f"    TP={m['tp']}  TN={m['tn']}  FP={m['fp']}  FN={m['fn']}")
        print(f"    Precision:         {m['precision']:.4f}")
        print(f"    Recall (strict):   {m['recall_strict']:.4f}  "
              f"(counts UNKNOWN-on-BUG as miss)")
        print(f"    Recall (lenient):  {m['recall_lenient']:.4f}  "
              f"(only among decided cases)")
        print(f"    F1 (strict):       {m['f1_strict']:.4f}")
        print(f"    F1 (lenient):      {m['f1_lenient']:.4f}")
        print(f"    Avg runtime:       {m['avg_runtime_sec']:.2f}s")

    if h2h:
        print(f"\n  HEAD-TO-HEAD")
        print(f"    A3 wins:         {h2h['a3_wins']}")
        print(f"    ESBMC wins:      {h2h['esbmc_wins']}")
        print(f"    Both correct:    {h2h['both_correct']}")
        print(f"    Both wrong:      {h2h['both_wrong']}")

    print()


if __name__ == "__main__":
    main()
