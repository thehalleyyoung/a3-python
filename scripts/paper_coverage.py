#!/usr/bin/env python3
"""
Paper Coverage Checker
======================

Runs A³ in kitchensink mode on every file in the BugsInPy evaluation set
AND the synthetic test suite, then reports which of the 20 SOTA papers
were actually exercised (i.e., produced at least one proof or finding).

Usage:
    python3 scripts/paper_coverage.py                       # full run
    python3 scripts/paper_coverage.py --suite synthetic      # synthetic only
    python3 scripts/paper_coverage.py --suite bugsinpy       # BugsInPy only
    python3 scripts/paper_coverage.py --limit 10             # first 10 files per suite
    python3 scripts/paper_coverage.py --timeout 60           # per-file timeout in seconds
    python3 scripts/paper_coverage.py --json results/paper_coverage.json

Outputs:
    results/paper_coverage.json   — structured data
    results/paper_coverage.md     — human-readable report
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Paths ───────────────────────────────────────────────────────────────
A3_ROOT        = Path(__file__).resolve().parent.parent
SUITE_ROOT     = A3_ROOT / "tests" / "synthetic_suite"
MANIFEST       = SUITE_ROOT / "GROUND_TRUTH_MANIFEST.json"
EXERCISE_ROOT  = A3_ROOT / "tests" / "paper_exercise_suite"
EXERCISE_MANIFEST = EXERCISE_ROOT / "PAPER_EXERCISE_MANIFEST.json"
BUGSINPY       = A3_ROOT / "BugsInPy"
BUGS_DIR       = BUGSINPY / "projects"
PYTHON         = sys.executable

# ── The 20 Papers ───────────────────────────────────────────────────────

PAPERS: Dict[int, str] = {
    1:  "HSCC'04 Hybrid Barrier Certificates",
    2:  "Stochastic Barrier Certificates",
    3:  "SOS Emptiness for Guarded Hazards",
    4:  "SOSTOOLS Framework",
    5:  "Putinar Positivstellensatz",
    6:  "Parrilo SOS-SDP",
    7:  "Lasserre Hierarchy",
    8:  "Sparse SOS (Clique Decomposition)",
    9:  "DSOS/SDSOS (LP/SOCP Relaxations)",
    10: "IC3/PDR (Property-Directed Reachability)",
    11: "Spacer/CHC (Horn Clause Solving)",
    12: "CEGAR (Counterexample-Guided Refinement)",
    13: "Predicate Abstraction",
    14: "Boolean Programs",
    15: "IMC / Craig Interpolants",
    16: "IMPACT / Lazy Abstraction",
    17: "ICE Learning (Data-Driven Invariants)",
    18: "Houdini (Conjunctive Inference)",
    19: "SyGuS (Syntax-Guided Synthesis)",
    20: "Assume-Guarantee Compositional Reasoning",
}

# Map known source tags → paper number(s)
SOURCE_TO_PAPERS: Dict[str, List[int]] = {
    "paper_1_hscc04_barrier":           [1],
    "paper_1_hscc04":                   [1],
    "paper_2_stochastic":               [2],
    "paper_3_sos_emptiness":            [3],
    "papers_4_5_putinar":               [4, 5],
    "papers_4_5_sostools_putinar":      [4, 5],
    "papers_6_7_8_sos":                 [6, 7, 8],
    "paper_6_parrilo":                  [6],
    "paper_7_lasserre":                 [7],
    "paper_8_sparse_sos":               [8],
    "paper_9_dsos_sdsos":               [9],
    "paper_10_ic3_pdr":                 [10],
    "paper_11_spacer_chc":              [11],
    "paper_12_cegar":                   [12],
    "paper_13_predicate_abstraction":   [13],
    "paper_14_boolean_programs":        [14],
    "paper_15_imc":                     [15],
    "paper_16_impact_lazy":             [16],
    "paper_17_ice":                     [17],
    "paper_18_houdini":                 [18],
    "paper_19_sygus":                   [19],
    "paper_20_assume_guarantee":        [20],
    # Composite / alternate tags
    "kitchensink_contract":             [20],       # contract bugs use AG
    "kitchensink_temporal":             [10, 18],   # temporal uses IC3 + Houdini
    "kitchensink_dataflow":             [13, 17],   # dataflow uses PA + ICE
    "kitchensink_protocol":             [12, 13],   # protocol uses CEGAR + PA
    "kitchensink_resource":             [7, 9],     # resource uses Lasserre + DSOS
}


def _papers_from_source(source: str) -> List[int]:
    """Extract paper numbers from a per_bug_type source tag."""
    if source in SOURCE_TO_PAPERS:
        return SOURCE_TO_PAPERS[source]
    # Fallback: parse "paper_N_..." pattern
    m = re.match(r"papers?_(\d+(?:_\d+)*)", source)
    if m:
        return [int(x) for x in m.group(1).split("_") if x.isdigit()]
    return []


# ── Data structures ─────────────────────────────────────────────────────

@dataclass
class FileResult:
    """Result of running kitchensink on one file."""
    file: str
    suite: str              # "synthetic" | "bugsinpy"
    bug_type: str           # Ground truth bug type (ASSERT_FAIL, DIV_ZERO, ...)
    expected: str           # "BUG" | "SAFE"
    verdict: str            # A³ verdict
    runtime_sec: float
    papers_exercised: List[int] = field(default_factory=list)
    per_bug_type_sources: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


# ── Runner ──────────────────────────────────────────────────────────────

@dataclass
class KSRunResult:
    """Full kitchensink run result including verbose paper tracking."""
    verdict: str
    runtime_sec: float
    per_bug_type: Dict[str, Any] = field(default_factory=dict)
    # Papers that produced proofs (strong exercise)
    proved_papers: Set[int] = field(default_factory=set)
    # Papers that were attempted but failed (weak exercise)
    attempted_papers: Set[int] = field(default_factory=set)
    # Papers that hit ImportError (broken wiring)
    import_failed_papers: Set[int] = field(default_factory=set)


# Regex patterns for parsing verbose kitchensink output
_RE_PAPER_SUCCESS = re.compile(r"✓\s+.*Paper\s*#?(\d+)|✓\s+(\w+)\s+SAFE", re.I)
_RE_PAPER_FAIL    = re.compile(r"✗\s+Paper\s*#(\d+).*?:\s*(\w+)")
_RE_PAPER_TRY     = re.compile(r"\[Paper\s*#(\d+)\]\s+Trying")
_RE_GOAL_PROOF    = re.compile(r"✓\s+(HSCC|SOS|Putinar|DSOS|Houdini|ICE|IC3|SyGuS|"
                               r"Unified SOS|Stochastic|Predicate|CEGAR|IMC|Spacer|"
                               r"Assume-Guarantee|Contract|Temporal|Data Flow|Protocol)")

# Map technique name → paper numbers
_TECHNIQUE_PAPERS = {
    "HSCC": [1], "SOS Emptiness": [3], "SOS": [3],
    "Putinar": [4, 5], "DSOS": [9], "SDSOS": [9],
    "Houdini": [18], "ICE": [17], "IC3": [10], "PDR": [10],
    "SyGuS": [19], "Unified SOS": [6, 7, 8],
    "Stochastic": [2], "Predicate": [13], "CEGAR": [12],
    "IMC": [15], "Spacer": [11], "CHC": [11],
    "Assume-Guarantee": [20], "Contract": [20],
    "Temporal": [10, 18], "Data Flow": [13, 17], "Protocol": [12, 13],
}


def _parse_verbose_output(text: str) -> Tuple[Set[int], Set[int], Set[int]]:
    """
    Parse kitchensink verbose output for paper exercise information.

    Returns (proved_papers, attempted_papers, import_failed_papers).
    """
    proved: Set[int] = set()
    attempted: Set[int] = set()
    import_failed: Set[int] = set()

    for line in text.splitlines():
        # Papers that succeeded (✓)
        for tech, papers in _TECHNIQUE_PAPERS.items():
            if f"✓" in line and tech in line:
                proved.update(papers)

        # Papers specifically noted as failing
        m = _RE_PAPER_FAIL.search(line)
        if m:
            pnum = int(m.group(1))
            error_type = m.group(2)
            if error_type == "ImportError":
                import_failed.add(pnum)
            attempted.add(pnum)

        # Papers attempted (GOAL 7 style)
        m = _RE_PAPER_TRY.search(line)
        if m:
            attempted.add(int(m.group(1)))

    return proved, attempted, import_failed


def run_kitchensink(file_path: Path, timeout_s: int = 60) -> KSRunResult:
    """
    Run A³ kitchensink on a single file (verbose mode), returning full paper tracking.

    Captures:
    - per_bug_type sources (proves which paper succeeded)
    - Verbose output parsing (which papers attempted/failed/succeeded)
    """
    snippet = textwrap.dedent("""\
        import json, sys
        from pathlib import Path
        from a3_python.analyzer import Analyzer

        p = Path(sys.argv[1])
        try:
            a = Analyzer(verbose=True, enable_concolic=True, enable_interprocedural=True)
            r = a.analyze_file_kitchensink(p)
            v = getattr(r, 'verdict', None) or 'UNKNOWN'
            bt = getattr(r, 'bug_type', '') or ''
            if v not in ('BUG', 'SAFE', 'UNKNOWN'):
                v = 'UNKNOWN'
            pbt = {}
            if hasattr(r, 'per_bug_type') and r.per_bug_type:
                for k, entry in r.per_bug_type.items():
                    if isinstance(entry, dict):
                        pbt[k] = {
                            'verdict': entry.get('verdict', ''),
                            'source': entry.get('source', ''),
                            'proof_count': len(entry.get('proofs', [])),
                        }
            print(json.dumps({'verdict': v, 'bug_type': bt, 'per_bug_type': pbt}))
        except BaseException as e:
            print(json.dumps({'verdict': 'ERROR', 'error': str(e)[:500]}))
    """)

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [PYTHON, "-c", snippet, str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
            cwd=str(A3_ROOT),
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        elapsed = time.perf_counter() - start

        # Parse verbose output for paper tracking (stdout + stderr)
        all_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        proved_v, attempted_v, import_failed_v = _parse_verbose_output(all_output)

        if proc.returncode != 0 and not proc.stdout.strip():
            return KSRunResult("ERROR", elapsed, {},
                               proved_v, attempted_v, import_failed_v)

        lines = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
        if not lines:
            return KSRunResult("ERROR", elapsed, {},
                               proved_v, attempted_v, import_failed_v)

        d = json.loads(lines[-1])
        v = d.get("verdict", "UNKNOWN")
        pbt = d.get("per_bug_type", {})

        # Also extract proved papers from per_bug_type sources
        for entry in pbt.values():
            src = entry.get("source", "")
            if src:
                proved_v.update(_papers_from_source(src))

        # Proved implies attempted — ensure attempted ⊇ proved
        attempted_v.update(proved_v)

        return KSRunResult(
            verdict=v if v in ("BUG", "SAFE", "UNKNOWN") else "UNKNOWN",
            runtime_sec=elapsed,
            per_bug_type=pbt,
            proved_papers=proved_v,
            attempted_papers=attempted_v,
            import_failed_papers=import_failed_v,
        )

    except subprocess.TimeoutExpired:
        return KSRunResult("UNKNOWN", time.perf_counter() - start)
    except Exception:
        return KSRunResult("ERROR", time.perf_counter() - start)


# ── Synthetic suite collector ───────────────────────────────────────────

def collect_synthetic_files(limit: Optional[int] = None) -> List[Tuple[Path, str, str]]:
    """
    Return [(file_path, bug_type, expected)] from the synthetic suite manifest.
    """
    if not MANIFEST.exists():
        print(f"[WARN] Manifest not found: {MANIFEST}")
        return []

    with open(MANIFEST) as f:
        manifest = json.load(f)

    bug_types = manifest.get("bug_types", {})
    entries: List[Tuple[Path, str, str]] = []

    for bt_name, files_dict in bug_types.items():
        bt_dir = SUITE_ROOT / bt_name
        for fname, meta in files_dict.items():
            if not isinstance(meta, dict):
                continue
            fpath = bt_dir / fname
            if fpath.exists():
                entries.append((fpath, bt_name, meta.get("expected", "UNKNOWN")))

    entries.sort(key=lambda x: str(x[0]))
    if limit:
        entries = entries[:limit]
    return entries


# ── Exercise suite collector ────────────────────────────────────────────

def collect_exercise_files(limit: Optional[int] = None) -> List[Tuple[Path, str, str]]:
    """
    Return [(file_path, bug_type, expected)] from the paper exercise suite manifest.
    """
    if not EXERCISE_MANIFEST.exists():
        print(f"[WARN] Exercise manifest not found: {EXERCISE_MANIFEST}")
        return []

    with open(EXERCISE_MANIFEST) as f:
        manifest = json.load(f)

    files_dict = manifest.get("files", {})
    entries: List[Tuple[Path, str, str]] = []

    for fname, meta in files_dict.items():
        if not isinstance(meta, dict):
            continue
        fpath = EXERCISE_ROOT / fname
        if fpath.exists():
            entries.append((fpath, meta.get("bug_type", "UNKNOWN"), meta.get("expected", "UNKNOWN")))

    entries.sort(key=lambda x: str(x[0]))
    if limit:
        entries = entries[:limit]
    return entries


# ── BugsInPy collector ──────────────────────────────────────────────────

def collect_bugsinpy_files(limit: Optional[int] = None) -> List[Tuple[Path, str, str]]:
    """
    Return [(file_path, project_bugid, expected)] from BugsInPy patches.

    For each bug we extract the buggy file (expected=BUG) and the fixed file
    (expected=SAFE).
    """
    if not BUGS_DIR.exists():
        print(f"[WARN] BugsInPy not found: {BUGS_DIR}")
        return []

    entries: List[Tuple[Path, str, str]] = []

    for project_dir in sorted(BUGS_DIR.iterdir()):
        if not project_dir.is_dir():
            continue
        bugs_subdir = project_dir / "bugs"
        if not bugs_subdir.exists():
            continue

        for bug_dir in sorted(bugs_subdir.iterdir()):
            if not bug_dir.is_dir():
                continue

            bug_id = bug_dir.name
            label = f"{project_dir.name}/{bug_id}"

            # Look for buggy / fixed Python files
            for variant, expected in [("buggy", "BUG"), ("fixed", "SAFE")]:
                variant_dir = bug_dir / variant
                if not variant_dir.exists():
                    # Try extracting from patch
                    patch_file = bug_dir / "bug_patch.txt"
                    if not patch_file.exists():
                        patch_file = bug_dir / "bug.patch"
                    continue

                for py in sorted(variant_dir.rglob("*.py")):
                    # Skip test files and __init__.py
                    if "test" in py.name.lower() or py.name == "__init__.py":
                        continue
                    entries.append((py, label, expected))

            if limit and len(entries) >= limit * 2:
                break
        if limit and len(entries) >= limit * 2:
            break

    if limit:
        entries = entries[:limit]
    return entries


# ── Main logic ──────────────────────────────────────────────────────────

def run_coverage(
    suites: List[str],
    limit: Optional[int] = None,
    timeout_s: int = 60,
) -> Dict[str, Any]:
    """Run kitchensink on all files and collect paper coverage."""

    all_results: List[FileResult] = []

    # Per-paper tracking
    paper_proved: Dict[int, List[str]] = defaultdict(list)     # strong: produced proof
    paper_attempted: Dict[int, List[str]] = defaultdict(list)  # weak: code path entered
    paper_import_failed: Dict[int, int] = defaultdict(int)     # ImportError count
    paper_proved_by_suite: Dict[str, Dict[int, List[str]]] = {
        "synthetic": defaultdict(list),
        "exercise": defaultdict(list),
        "bugsinpy": defaultdict(list),
    }

    files_to_run: List[Tuple[Path, str, str, str]] = []  # (path, bt, expected, suite)

    if "synthetic" in suites:
        for fpath, bt, expected in collect_synthetic_files(limit):
            files_to_run.append((fpath, bt, expected, "synthetic"))

    if "exercise" in suites:
        for fpath, bt, expected in collect_exercise_files(limit):
            files_to_run.append((fpath, bt, expected, "exercise"))

    if "bugsinpy" in suites:
        for fpath, label, expected in collect_bugsinpy_files(limit):
            files_to_run.append((fpath, label, expected, "bugsinpy"))

    total = len(files_to_run)
    print(f"\n{'='*70}")
    print(f"  Paper Coverage Checker — {total} files across {suites}")
    print(f"{'='*70}\n")

    for i, (fpath, bt, expected, suite) in enumerate(files_to_run, 1):
        short = fpath.name
        print(f"  [{i:4d}/{total}] {suite:10s}  {short:50s}", end="", flush=True)

        ks = run_kitchensink(fpath, timeout_s)

        # Extract paper sources from per_bug_type
        sources: Dict[str, str] = {}
        for bug_type_key, entry in ks.per_bug_type.items():
            if bug_type_key.startswith("_"):
                continue
            source = entry.get("source", "")
            sources[bug_type_key] = source

        papers_found = ks.proved_papers

        # Record
        result = FileResult(
            file=str(fpath.relative_to(A3_ROOT)),
            suite=suite,
            bug_type=bt,
            expected=expected,
            verdict=ks.verdict,
            runtime_sec=round(ks.runtime_sec, 3),
            papers_exercised=sorted(papers_found),
            per_bug_type_sources=sources,
            error=None,
        )
        all_results.append(result)

        # Update per-paper tracking
        for p in ks.proved_papers:
            paper_proved[p].append(str(fpath.relative_to(A3_ROOT)))
            paper_proved_by_suite[suite][p].append(str(fpath.relative_to(A3_ROOT)))
        for p in ks.attempted_papers:
            paper_attempted[p].append(str(fpath.relative_to(A3_ROOT)))
        for p in ks.import_failed_papers:
            paper_import_failed[p] += 1

        np = len(ks.proved_papers)
        na = len(ks.attempted_papers)
        if np == 0:
            proved_str = "0/20"
        elif np <= 5:
            proved_str = ",".join(f"#{p}" for p in sorted(ks.proved_papers))
        else:
            proved_str = f"{np}/20"
        failed_str = f" import_err={len(ks.import_failed_papers)}" if ks.import_failed_papers else ""
        print(f"  {ks.verdict:7s}  papers={proved_str}{failed_str}  ({ks.runtime_sec:.1f}s)")

    # ── Aggregate ───────────────────────────────────────────────────────
    coverage = {}
    for paper_num in range(1, 21):
        proved = paper_proved.get(paper_num, [])
        attempted = paper_attempted.get(paper_num, [])
        syn_proved = paper_proved_by_suite["synthetic"].get(paper_num, [])
        ex_proved = paper_proved_by_suite["exercise"].get(paper_num, [])
        bip_proved = paper_proved_by_suite["bugsinpy"].get(paper_num, [])
        import_fails = paper_import_failed.get(paper_num, 0)
        coverage[paper_num] = {
            "name": PAPERS[paper_num],
            "proved_hits": len(proved),
            "attempted_hits": len(attempted),
            "import_failures": import_fails,
            "synthetic_proved": len(syn_proved),
            "exercise_proved": len(ex_proved),
            "bugsinpy_proved": len(bip_proved),
            "exercised": len(proved) > 0,
            "attempted": len(attempted) > 0,
            "sample_files": proved[:5],
        }

    papers_exercised = [p for p in range(1, 21) if coverage[p]["exercised"]]
    papers_attempted_only = [p for p in range(1, 21)
                            if coverage[p]["attempted"] and not coverage[p]["exercised"]]
    papers_missing = [p for p in range(1, 21)
                     if not coverage[p]["exercised"] and not coverage[p]["attempted"]]

    report = {
        "timestamp": datetime.now().isoformat(),
        "suites": suites,
        "total_files": total,
        "timeout_sec": timeout_s,
        "papers_exercised": papers_exercised,
        "papers_attempted_only": papers_attempted_only,
        "papers_missing": papers_missing,
        "coverage_fraction": f"{len(papers_exercised)}/20",
        "coverage_pct": round(100 * len(papers_exercised) / 20, 1),
        "attempted_fraction": f"{len(papers_exercised) + len(papers_attempted_only)}/20",
        "per_paper": {str(k): v for k, v in coverage.items()},
        "details": [asdict(r) for r in all_results],
    }
    return report


def generate_md(report: Dict[str, Any]) -> str:
    """Generate Markdown report from coverage data."""
    lines: List[str] = []
    lines.append("# A³ Paper Coverage Report\n")
    lines.append(f"**Date:** {report['timestamp']}")
    lines.append(f"**Suites:** {', '.join(report['suites'])}")
    lines.append(f"**Files analyzed:** {report['total_files']}")
    lines.append(f"**Timeout:** {report['timeout_sec']}s per file")
    lines.append(f"**Papers with proofs:** {report['coverage_fraction']} "
                 f"({report['coverage_pct']}%)")
    lines.append(f"**Papers attempted (incl. failures):** "
                 f"{report['attempted_fraction']}\n")

    # ── Summary table ───────────────────────────────────────────────────
    lines.append("## Coverage Matrix\n")
    lines.append("| # | Paper | Proved | Attempted | ImportErr | Synthetic | Exercise | BugsInPy |")
    lines.append("|--:|-------|:------:|----------:|----------:|----------:|---------:|---------:|")

    per_paper = report["per_paper"]
    for num in range(1, 21):
        p = per_paper[str(num)]
        check = "✅" if p["exercised"] else ("⚠️" if p["attempted"] else "❌")
        lines.append(
            f"| {num} | {p['name']} | {check} | {p['attempted_hits']} "
            f"| {p['import_failures']} | {p['synthetic_proved']} "
            f"| {p.get('exercise_proved', 0)} | {p['bugsinpy_proved']} |"
        )

    # ── Tri-state breakdown ─────────────────────────────────────────────
    exercised = report.get("papers_exercised", [])
    attempted_only = report.get("papers_attempted_only", [])
    missing = report.get("papers_missing", [])

    if exercised:
        lines.append(f"\n## ✅ Papers Producing Proofs ({len(exercised)})\n")
        for num in exercised:
            p = per_paper[str(num)]
            lines.append(f"- **Paper #{num}: {p['name']}** — "
                         f"{p['proved_hits']} proofs "
                         f"({p['synthetic_proved']} synthetic, "
                         f"{p['bugsinpy_proved']} BugsInPy)")

    if attempted_only:
        lines.append(f"\n## ⚠️ Papers Attempted but No Proofs ({len(attempted_only)})\n")
        lines.append("> These papers' code paths are entered but either hit "
                     "`ImportError` or produce no results.\n")
        for num in attempted_only:
            p = per_paper[str(num)]
            ie = p['import_failures']
            reason = f" — **{ie} ImportErrors**" if ie else ""
            lines.append(f"- **Paper #{num}: {p['name']}**"
                         f" — attempted {p['attempted_hits']} times{reason}")

    if missing:
        lines.append(f"\n## ❌ Papers Never Reached ({len(missing)})\n")
        lines.append("> No test file triggered these papers' code paths.\n")
        for num in missing:
            p = per_paper[str(num)]
            lines.append(f"- **Paper #{num}: {p['name']}**")

    return "\n".join(lines)


# ── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="A³ Paper Coverage Checker")
    parser.add_argument("--suite", nargs="*", default=["synthetic", "exercise", "bugsinpy"],
                        choices=["synthetic", "exercise", "bugsinpy"],
                        help="Which suites to include (default: all three)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Max files per suite (for quick smoke tests)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Per-file timeout in seconds (default: 60)")
    parser.add_argument("--json", type=str, default=None,
                        help="Path for JSON output (default: results/paper_coverage.json)")
    parser.add_argument("--md", type=str, default=None,
                        help="Path for Markdown output (default: results/paper_coverage.md)")
    args = parser.parse_args()

    json_path = Path(args.json) if args.json else A3_ROOT / "results" / "paper_coverage.json"
    md_path = Path(args.md) if args.md else A3_ROOT / "results" / "paper_coverage.md"

    report = run_coverage(args.suite, limit=args.limit, timeout_s=args.timeout)

    # Write JSON
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[JSON] {json_path}")

    # Write Markdown
    md_text = generate_md(report)
    with open(md_path, "w") as f:
        f.write(md_text)
    print(f"[MD]   {md_path}")

    # Print summary
    print(f"\n{'='*70}")
    print(f"  PAPER COVERAGE: {report['coverage_fraction']} proved "
          f"({report['coverage_pct']}%)  |  "
          f"{report['attempted_fraction']} attempted")
    print(f"{'='*70}")
    exercised = report["papers_exercised"]
    attempted_only = report.get("papers_attempted_only", [])
    missing = report.get("papers_missing", [])
    if exercised:
        print(f"  ✅ Proved:        {', '.join(f'#{p}' for p in exercised)}")
    if attempted_only:
        print(f"  ⚠️  Attempted-only: {', '.join(f'#{p}' for p in attempted_only)}")
    if missing:
        print(f"  ❌ Never reached: {', '.join(f'#{p}' for p in missing)}")
    print()


if __name__ == "__main__":
    main()
