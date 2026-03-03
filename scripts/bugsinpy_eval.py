#!/usr/bin/env python3
"""
BugsInPy Evaluation Orchestrator for a3-python
================================================

For every bug in the BugsInPy benchmark:
  1. Extract the *buggy* and *fixed* Python file(s) from the patch
  2. Run a3-python on each
  3. Check:
       buggy  → a3 should report BUG  (else False Negative)
       fixed  → a3 should report SAFE (else False Positive)
  4. For every incorrect result, generate a copilot-cli prompt
     that describes the gap and asks copilot to improve a3-python

Unlike the heavier iterative_bugsinpy_improve.py (which clones full repos
and invokes copilot to self-patch), this script is a *pure evaluator*:
it extracts only the changed files from the patch, runs a3, records
the result, and writes an actionable report + prompts.  No repo
cloning is required — the patch itself is the source of truth.

Usage:
    python scripts/bugsinpy_eval.py                     # all bugs
    python scripts/bugsinpy_eval.py --projects ansible black
    python scripts/bugsinpy_eval.py --limit 20          # first 20 bugs
    python scripts/bugsinpy_eval.py --out results/bugsinpy_eval.md
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Paths ───────────────────────────────────────────────────────────────────
A3_ROOT    = Path(__file__).resolve().parent.parent
BUGSINPY   = A3_ROOT / "BugsInPy"
BUGS_DIR   = BUGSINPY / "projects"

ALL_PROJECTS = sorted(
    d.name for d in BUGS_DIR.iterdir() if d.is_dir()
) if BUGS_DIR.exists() else []

# ═══════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class A3Finding:
    bug_type: str
    file: str
    line: int
    message: str
    confidence: float = 0.0


@dataclass
class ScanResult:
    """Result of running a3-python on a single file."""
    file: str
    exit_code: int                         # 0=SAFE 1=BUG 2=UNKNOWN 3=ERROR
    verdict: str                           # SAFE | BUG | UNKNOWN | ERROR
    findings: List[A3Finding] = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None
    duration_sec: float = 0.0


@dataclass
class BugEvalResult:
    """Evaluation of one BugsInPy bug."""
    project: str
    bug_id: int
    # Bug metadata
    buggy_commit: str = ""
    fixed_commit: str = ""
    test_file: str = ""
    python_version: str = ""
    changed_files: List[str] = field(default_factory=list)
    # Scan results (per changed file)
    buggy_scans: List[ScanResult] = field(default_factory=list)
    fixed_scans: List[ScanResult] = field(default_factory=list)
    # Classification
    a3_correct: bool = False
    classification: str = "NOT_RUN"
    # TRUE_POSITIVE  – a3 finds bug pre-fix, clean post-fix  ✓
    # FALSE_NEGATIVE – a3 misses the bug (buggy scans clean)
    # FALSE_POSITIVE – a3 flags fixed code (fixed scans BUG)
    # BOTH_BUG       – a3 flags both (doesn't see the fix)
    # BOTH_CLEAN     – same as FALSE_NEGATIVE (neither flagged)
    # ERROR          – a3 crashed / timed out
    # NO_PATCH       – no Python files in patch
    detail: str = ""
    # Generated prompt (empty if a3 was correct)
    improvement_prompt: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Patch extraction
# ═══════════════════════════════════════════════════════════════════════════

def _parse_patch(patch_text: str) -> Dict[str, Tuple[str, str]]:
    """
    Parse a unified diff into {filename: (buggy_content, fixed_content)}.

    Returns per-file content: *buggy* = content with '-' lines kept,
    '+' lines removed; *fixed* = content with '+' lines kept, '-' removed.
    We only keep .py files.
    """
    files: Dict[str, Tuple[List[str], List[str]]] = {}
    current_file: Optional[str] = None
    buggy_lines: List[str] = []
    fixed_lines: List[str] = []

    for line in patch_text.splitlines(keepends=True):
        # New file header
        if line.startswith("diff --git"):
            # Save previous file
            if current_file is not None:
                files[current_file] = (buggy_lines, fixed_lines)
            parts = line.split()
            if len(parts) >= 4:
                raw = parts[3]
                current_file = raw.lstrip("b/") if raw.startswith("b/") else raw
            else:
                current_file = None
            buggy_lines = []
            fixed_lines = []
            continue

        if current_file is None:
            continue

        # Skip diff metadata lines
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("@@"):
            # Add a comment marker so the code is parseable
            buggy_lines.append("# @@ hunk @@\n")
            fixed_lines.append("# @@ hunk @@\n")
            continue

        if line.startswith("-"):
            buggy_lines.append(line[1:])            # in buggy only
        elif line.startswith("+"):
            fixed_lines.append(line[1:])             # in fixed only
        else:
            # context line (space-prefixed or no-prefix)
            content = line[1:] if line.startswith(" ") else line
            buggy_lines.append(content)
            fixed_lines.append(content)

    # Save last file
    if current_file is not None:
        files[current_file] = (buggy_lines, fixed_lines)

    # Filter to .py only and convert to strings
    result: Dict[str, Tuple[str, str]] = {}
    for fname, (blines, flines) in files.items():
        if fname.endswith(".py") and not _is_test_file(fname):
            result[fname] = ("".join(blines), "".join(flines))
    return result


def _is_test_file(path: str) -> bool:
    """Heuristic: skip test files."""
    parts = Path(path).parts
    name = Path(path).name.lower()
    return (
        name.startswith("test_")
        or name.startswith("tests")
        or name == "conftest.py"
        or "test" in parts
        or "tests" in parts
        or "testing" in parts
    )


# ═══════════════════════════════════════════════════════════════════════════
# Bug metadata
# ═══════════════════════════════════════════════════════════════════════════

def list_bugs(project: str) -> List[int]:
    bugs_dir = BUGS_DIR / project / "bugs"
    if not bugs_dir.exists():
        return []
    return sorted(int(d.name) for d in bugs_dir.iterdir() if d.is_dir() and d.name.isdigit())


def read_info(path: Path) -> Dict[str, str]:
    info: Dict[str, str] = {}
    if not path.exists():
        return info
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            info[k.strip()] = v.strip().strip('"')
    return info


# ═══════════════════════════════════════════════════════════════════════════
# a3-python runner
# ═══════════════════════════════════════════════════════════════════════════

A3_TIMEOUT = 90  # seconds per file


def run_a3(filepath: Path, verbose: bool = False) -> ScanResult:
    """Run a3-python on a single file and return structured result."""
    t0 = time.monotonic()
    cmd = [sys.executable, "-m", "a3_python", str(filepath),
           "--functions", "--deduplicate", "--min-confidence", "0.3"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=A3_TIMEOUT,
            cwd=str(A3_ROOT),
        )
        raw = proc.stdout + proc.stderr
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        return ScanResult(
            file=str(filepath), exit_code=3, verdict="ERROR",
            error=f"timeout ({A3_TIMEOUT}s)", duration_sec=time.monotonic() - t0,
        )
    except Exception as exc:
        return ScanResult(
            file=str(filepath), exit_code=3, verdict="ERROR",
            error=str(exc), duration_sec=time.monotonic() - t0,
        )

    verdict_map = {0: "SAFE", 1: "BUG", 2: "UNKNOWN"}
    verdict = verdict_map.get(exit_code, "ERROR")
    findings = _parse_findings(raw, str(filepath))

    return ScanResult(
        file=str(filepath),
        exit_code=exit_code,
        verdict=verdict,
        findings=findings,
        raw_output=raw[:4000],
        duration_sec=time.monotonic() - t0,
    )


def _parse_findings(output: str, file_hint: str) -> List[A3Finding]:
    """Extract bug reports from a3's human-readable stdout."""
    findings: List[A3Finding] = []
    patterns = [
        re.compile(
            r"\[BUG\]\s+(?P<bt>[A-Z_]+)\s+\(line\s+(?P<ln>\d+)"
            r"(?:,\s*confidence\s+(?P<conf>[\d.]+))?",
            re.I,
        ),
        re.compile(
            r"(?:bug|BUG)[:]\s*(?P<bt>[A-Z_]+).*?(?:line|at line)\s+(?P<ln>\d+)", re.I
        ),
        re.compile(
            r"Found bug[:]\s*(?P<bt>[A-Z_]+).*?on line\s+(?P<ln>\d+)", re.I
        ),
        re.compile(
            r"^\s+(?P<bt>[A-Z][A-Z_]{2,})[:]\s+line\s+(?P<ln>\d+)"
        ),
        re.compile(
            r"(?P<bt>SQL_INJECTION|SSRF|DIVIDE_BY_ZERO|NULL_DEREF|BUFFER_OVERFLOW"
            r"|PATH_TRAVERSAL|COMMAND_INJECTION|XSS|RACE_CONDITION|USE_AFTER_FREE"
            r"|FORMAT_STRING|UNSAFE|INDEX_OUT_OF_RANGE|TYPE_ERROR"
            r"|ATTRIBUTE_ERROR|KEY_ERROR|UNHANDLED_EXCEPTION|VALUE_ERROR"
            r"|ASSERTION_ERROR|RECURSION|INFINITE_LOOP|DEADLOCK)"
            r"[^\n]*?line\s+(?P<ln>\d+)",
            re.I,
        ),
    ]
    for raw_line in output.splitlines():
        for pat in patterns:
            m = pat.search(raw_line)
            if m:
                bt = m.group("bt").upper()
                ln = int(m.group("ln")) if m.group("ln") else 0
                conf = float(m.group("conf")) if "conf" in m.groupdict() and m.group("conf") else 0.0
                findings.append(A3Finding(
                    bug_type=bt, file=file_hint, line=ln,
                    message=raw_line.strip(), confidence=conf,
                ))
                break
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Classification
# ═══════════════════════════════════════════════════════════════════════════

def classify(buggy_scans: List[ScanResult], fixed_scans: List[ScanResult]) -> Tuple[str, bool, str]:
    """
    Classify a3's performance on one BugsInPy bug.

    Returns (classification, a3_correct, detail_string).
    """
    buggy_has_bug = any(s.verdict == "BUG" for s in buggy_scans)
    fixed_has_bug = any(s.verdict == "BUG" for s in fixed_scans)
    buggy_error   = all(s.verdict == "ERROR" for s in buggy_scans) if buggy_scans else True
    fixed_error   = all(s.verdict == "ERROR" for s in fixed_scans) if fixed_scans else True

    if buggy_error and fixed_error:
        return "ERROR", False, "a3 crashed/timed out on both versions"

    buggy_findings = [f for s in buggy_scans for f in s.findings]
    fixed_findings = [f for s in fixed_scans for f in s.findings]

    if buggy_has_bug and not fixed_has_bug:
        return "TRUE_POSITIVE", True, (
            f"a3 correctly found {len(buggy_findings)} bug(s) pre-fix "
            f"and reported clean post-fix"
        )

    if not buggy_has_bug and not fixed_has_bug:
        return "FALSE_NEGATIVE", False, (
            f"a3 missed the bug — reported SAFE on both versions "
            f"(buggy verdicts: {[s.verdict for s in buggy_scans]})"
        )

    if not buggy_has_bug and fixed_has_bug:
        return "FALSE_POSITIVE", False, (
            f"a3 missed the bug pre-fix but flagged the fixed code "
            f"({len(fixed_findings)} finding(s)) — false positive"
        )

    # Both have bugs
    buggy_sigs = {(f.bug_type, f.line) for f in buggy_findings}
    fixed_sigs = {(f.bug_type, f.line) for f in fixed_findings}
    disappeared = buggy_sigs - fixed_sigs
    if disappeared:
        return "TRUE_POSITIVE", True, (
            f"a3 found bugs in both, but {len(disappeared)} finding(s) "
            f"resolved post-fix (correctly detected the fix)"
        )
    return "BOTH_BUG", False, (
        f"a3 reports the same {len(buggy_findings)} bug(s) on both "
        f"versions — fails to recognise the fix was applied"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Prompt generation
# ═══════════════════════════════════════════════════════════════════════════

def make_improvement_prompt(ev: BugEvalResult) -> str:
    """
    Build a copilot-cli prompt specific to the failure on this bug,
    asking copilot to improve a3-python's analysis.
    """
    if ev.a3_correct:
        return ""

    patch_file = BUGS_DIR / ev.project / "bugs" / str(ev.bug_id) / "bug_patch.txt"
    patch_snippet = ""
    if patch_file.exists():
        raw = patch_file.read_text(errors="replace")
        patch_snippet = raw[:3000]

    buggy_output = "\n".join(
        s.raw_output[:800] for s in ev.buggy_scans if s.raw_output
    )[:2000]
    fixed_output = "\n".join(
        s.raw_output[:800] for s in ev.fixed_scans if s.raw_output
    )[:2000]

    buggy_findings_str = "\n".join(
        f"  [{f.bug_type}] line {f.line}: {f.message[:120]}"
        for s in ev.buggy_scans for f in s.findings
    ) or "  (none)"
    fixed_findings_str = "\n".join(
        f"  [{f.bug_type}] line {f.line}: {f.message[:120]}"
        for s in ev.fixed_scans for f in s.findings
    ) or "  (none)"

    if ev.classification in ("FALSE_NEGATIVE", "BOTH_CLEAN"):
        task = textwrap.dedent(f"""\
        PROBLEM: FALSE NEGATIVE — a3-python failed to detect a known bug.

        Project: {ev.project}
        Bug ID : {ev.bug_id}  (BugsInPy benchmark)
        Test   : {ev.test_file}
        Changed files: {', '.join(ev.changed_files)}

        The buggy commit ({ev.buggy_commit[:10]}) contains a real bug that is
        fixed in commit {ev.fixed_commit[:10]}.  a3-python reported SAFE on the
        buggy code, meaning it missed the bug entirely.

        a3 findings on BUGGY code:
        {buggy_findings_str}

        a3 findings on FIXED code:
        {fixed_findings_str}

        Bug patch (what was changed to fix the bug):
        ```
        {patch_snippet}
        ```

        a3 raw output on buggy code (excerpt):
        {buggy_output[:1000]}

        TASK:
        1. Read the bug patch above and understand what class of bug it
           represents (e.g., missing validation, unchecked None, key error,
           type confusion, off-by-one, missing condition, etc.).
        2. Inspect the a3_python/ source code (especially unsafe/registry.py,
           semantics/symbolic_vm.py, analyzer.py) and identify WHY a3 missed it.
           Common root causes:
             - The bug type is not in the unsafe checker registry
             - The symbolic VM doesn't model the relevant built-in
             - CFG construction skips the relevant code path
             - Taint propagation doesn't cover the data flow involved
        3. Implement a targeted fix in a3-python so it detects this class of
           bug.  Keep changes minimal but correct.  Do NOT break existing
           passing tests.
        """)

    elif ev.classification in ("FALSE_POSITIVE",):
        task = textwrap.dedent(f"""\
        PROBLEM: FALSE POSITIVE — a3-python flags correct (fixed) code as buggy.

        Project: {ev.project}
        Bug ID : {ev.bug_id}  (BugsInPy benchmark)
        Test   : {ev.test_file}
        Changed files: {', '.join(ev.changed_files)}

        The fixed commit ({ev.fixed_commit[:10]}) is correct code, yet a3
        reports bug(s) on it.

        a3 findings on BUGGY code:
        {buggy_findings_str}

        a3 findings on FIXED code (these are false positives):
        {fixed_findings_str}

        Bug patch (context):
        ```
        {patch_snippet}
        ```

        a3 raw output on fixed code (excerpt):
        {fixed_output[:1000]}

        TASK:
        1. Read the false-positive findings above and the fixed code.
        2. Identify which a3 checker produced the incorrect report and why
           it fails to recognise the safe pattern.
        3. Add a filter, guard, or precision improvement in a3_python/
           so this false positive no longer fires.  Do NOT suppress real bugs.
        """)

    elif ev.classification == "BOTH_BUG":
        task = textwrap.dedent(f"""\
        PROBLEM: a3 reports the same bugs on BOTH buggy and fixed versions.

        Project: {ev.project}
        Bug ID : {ev.bug_id}  (BugsInPy benchmark)
        Changed files: {', '.join(ev.changed_files)}

        a3 findings on BUGGY code:
        {buggy_findings_str}

        a3 findings on FIXED code:
        {fixed_findings_str}

        This means a3 either:
          a) Found a pre-existing issue unrelated to this bug (and
             simultaneously missed the actual BugsInPy bug → false negative), or
          b) Doesn't recognise that the fix resolves the finding.

        Bug patch:
        ```
        {patch_snippet}
        ```

        TASK:
        1. Determine whether the findings are related to the BugsInPy bug
           or are unrelated pre-existing issues.
        2. If unrelated: improve a3 to also catch the actual bug described
           by the patch (see FALSE NEGATIVE guidance).
        3. If related but not cleared by the fix: improve a3's flow-sensitivity
           or guard recognition so the finding resolves post-fix.
        """)
    else:
        task = f"Classification: {ev.classification}\nDetail: {ev.detail}"

    return textwrap.dedent(f"""\
    You are improving a3-python, a Python static analyser located in the
    a3_python/ directory of this workspace.  This prompt was auto-generated
    by the BugsInPy evaluation orchestrator.

    {task}
    """).strip()


# ═══════════════════════════════════════════════════════════════════════════
# Main evaluation loop
# ═══════════════════════════════════════════════════════════════════════════

import tempfile


def evaluate_bug(project: str, bug_id: int, *, verbose: bool = False) -> BugEvalResult:
    """Evaluate a3-python on one BugsInPy bug using patch extraction."""
    bug_dir = BUGS_DIR / project / "bugs" / str(bug_id)
    bug_info = read_info(bug_dir / "bug.info")
    # project_info = read_info(BUGS_DIR / project / "project.info")

    ev = BugEvalResult(
        project=project,
        bug_id=bug_id,
        buggy_commit=bug_info.get("buggy_commit_id", ""),
        fixed_commit=bug_info.get("fixed_commit_id", ""),
        test_file=bug_info.get("test_file", ""),
        python_version=bug_info.get("python_version", ""),
    )

    # Read patch
    patch_path = bug_dir / "bug_patch.txt"
    if not patch_path.exists():
        ev.classification = "NO_PATCH"
        ev.detail = "bug_patch.txt not found"
        return ev

    patch_text = patch_path.read_text(errors="replace")
    file_versions = _parse_patch(patch_text)
    if not file_versions:
        ev.classification = "NO_PATCH"
        ev.detail = "No Python source files in patch (only tests?)"
        return ev

    ev.changed_files = list(file_versions.keys())

    # Write extracted files to a temp dir and scan
    with tempfile.TemporaryDirectory(prefix="a3_beval_") as tmpdir:
        tmp = Path(tmpdir)
        buggy_dir = tmp / "buggy"
        fixed_dir = tmp / "fixed"
        buggy_dir.mkdir()
        fixed_dir.mkdir()

        for fname, (buggy_src, fixed_src) in file_versions.items():
            # Create sub-directories matching original path
            bp = buggy_dir / fname
            fp = fixed_dir / fname
            bp.parent.mkdir(parents=True, exist_ok=True)
            fp.parent.mkdir(parents=True, exist_ok=True)
            bp.write_text(buggy_src, encoding="utf-8")
            fp.write_text(fixed_src, encoding="utf-8")

        # Scan buggy files
        for fname in file_versions:
            sr = run_a3(buggy_dir / fname, verbose=verbose)
            ev.buggy_scans.append(sr)

        # Scan fixed files
        for fname in file_versions:
            sr = run_a3(fixed_dir / fname, verbose=verbose)
            ev.fixed_scans.append(sr)

    # Classify
    ev.classification, ev.a3_correct, ev.detail = classify(
        ev.buggy_scans, ev.fixed_scans,
    )

    # Generate improvement prompt if a3 was wrong
    if not ev.a3_correct:
        ev.improvement_prompt = make_improvement_prompt(ev)

    return ev


def run_evaluation(
    projects: List[str],
    limit: int,
    verbose: bool,
    json_path: Optional[Path] = None,
) -> List[BugEvalResult]:
    """Evaluate all requested bugs and return results.

    Saves incremental JSON after each bug so results survive Ctrl+C.
    """
    results: List[BugEvalResult] = []
    count = 0
    for project in projects:
        bug_ids = list_bugs(project)
        for bug_id in bug_ids:
            if limit and count >= limit:
                return results
            count += 1
            label = f"[{count}] {project}/bug#{bug_id}"
            if verbose:
                print(f"  {label} …", end=" ", flush=True)
            ev = evaluate_bug(project, bug_id, verbose=verbose)
            results.append(ev)
            mark = "✓" if ev.a3_correct else "✗"
            dur = sum(s.duration_sec for s in ev.buggy_scans + ev.fixed_scans)
            print(
                f"  {mark} {label:30s}  {ev.classification:18s}  "
                f"({len(ev.changed_files)} files, {dur:.1f}s)"
            )
            # Incremental save so results survive Ctrl+C
            if json_path:
                save_json(results, json_path)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Report generation
# ═══════════════════════════════════════════════════════════════════════════

def generate_report(results: List[BugEvalResult], out: Path) -> str:
    total     = len(results)
    correct   = sum(1 for r in results if r.a3_correct)
    fn        = sum(1 for r in results if r.classification == "FALSE_NEGATIVE")
    fp        = sum(1 for r in results if r.classification == "FALSE_POSITIVE")
    both_bug  = sum(1 for r in results if r.classification == "BOTH_BUG")
    no_patch  = sum(1 for r in results if r.classification == "NO_PATCH")
    errors    = sum(1 for r in results if r.classification == "ERROR")
    tp        = correct

    lines = [
        "# BugsInPy Evaluation Report — a3-python",
        f"_Generated: {datetime.now().isoformat(timespec='seconds')}_\n",
        "## Summary\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total bugs evaluated | {total} |",
        f"| **True Positive** (a3 correct) | {tp} |",
        f"| **False Negative** (a3 missed bug) | {fn} |",
        f"| **False Positive** (a3 flagged fixed code) | {fp} |",
        f"| Both Bug (same finding pre & post) | {both_bug} |",
        f"| No Python patch files | {no_patch} |",
        f"| Error / timeout | {errors} |",
        "",
        f"**Detection rate**: {tp}/{tp+fn+both_bug} = "
        f"{tp/(tp+fn+both_bug)*100:.1f}%" if (tp+fn+both_bug) > 0 else "",
        f"**Precision (no FP)**: {tp}/{tp+fp+both_bug} = "
        f"{tp/(tp+fp+both_bug)*100:.1f}%" if (tp+fp+both_bug) > 0 else "",
        "",
    ]

    # Per-project breakdown
    from collections import Counter, defaultdict
    proj_stats: Dict[str, Dict[str, int]] = defaultdict(Counter)
    for r in results:
        proj_stats[r.project][r.classification] += 1

    lines += [
        "## Per-Project Breakdown\n",
        "| Project | TP | FN | FP | Both | NoPatch | Err | Total |",
        "|---------|----|----|----|----- |---------|-----|-------|",
    ]
    for proj in sorted(proj_stats):
        s = proj_stats[proj]
        lines.append(
            f"| {proj} | {s.get('TRUE_POSITIVE',0)} | {s.get('FALSE_NEGATIVE',0)} "
            f"| {s.get('FALSE_POSITIVE',0)} | {s.get('BOTH_BUG',0)} "
            f"| {s.get('NO_PATCH',0)} | {s.get('ERROR',0)} "
            f"| {sum(s.values())} |"
        )

    # Detail table
    lines += [
        "", "## Per-Bug Detail\n",
        "| # | Project | Bug | Class | Files | Detail |",
        "|---|---------|-----|-------|-------|--------|",
    ]
    for i, r in enumerate(results, 1):
        cls_emoji = {
            "TRUE_POSITIVE": "✅", "FALSE_NEGATIVE": "❌",
            "FALSE_POSITIVE": "⚠️", "BOTH_BUG": "🔁",
            "NO_PATCH": "—", "ERROR": "💥",
        }.get(r.classification, "?")
        lines.append(
            f"| {i} | {r.project} | {r.bug_id} | {cls_emoji} {r.classification} "
            f"| {len(r.changed_files)} | {r.detail[:80]} |"
        )

    # Improvement prompts
    prompts = [(r, r.improvement_prompt) for r in results if r.improvement_prompt]
    if prompts:
        lines += ["", "---", "", "## Improvement Prompts for Copilot CLI\n"]
        for r, prompt in prompts:
            lines += [
                f"### {r.project} bug #{r.bug_id} — {r.classification}\n",
                "```",
                prompt,
                "```",
                "",
            ]

    # Aggregate improvement prompt
    lines += [
        "", "---", "",
        "## Aggregate Improvement Prompt\n",
        "```",
        _aggregate_prompt(results),
        "```",
    ]

    report = "\n".join(lines)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    return report


def _aggregate_prompt(results: List[BugEvalResult]) -> str:
    fn_examples = [r for r in results if r.classification == "FALSE_NEGATIVE"][:10]
    fp_examples = [r for r in results if r.classification == "FALSE_POSITIVE"][:10]
    bb_examples = [r for r in results if r.classification == "BOTH_BUG"][:5]
    tp_count = sum(1 for r in results if r.a3_correct)
    fn_count = sum(1 for r in results if r.classification == "FALSE_NEGATIVE")
    fp_count = sum(1 for r in results if r.classification == "FALSE_POSITIVE")

    fn_lines = "\n".join(
        f"  - {r.project} bug#{r.bug_id}: files={', '.join(r.changed_files[:3])}"
        for r in fn_examples
    ) or "  (none)"

    fp_lines = "\n".join(
        f"  - {r.project} bug#{r.bug_id}: "
        + ", ".join(f"[{f.bug_type}]" for s in r.fixed_scans for f in s.findings)[:120]
        for r in fp_examples
    ) or "  (none)"

    return textwrap.dedent(f"""\
    You are improving a3-python, a Python static analyser (workspace: a3_python/).
    This prompt summarises the BugsInPy evaluation results.

    Overall:
      True Positives : {tp_count}
      False Negatives: {fn_count}
      False Positives: {fp_count}

    FALSE NEGATIVES (bugs a3 missed — highest priority):
    {fn_lines}

    FALSE POSITIVES (fixed code a3 incorrectly flagged):
    {fp_lines}

    Priority tasks:
    1. For each false-negative class of bug, add or extend an unsafe
       checker in a3_python/unsafe/registry.py (or the appropriate
       module) so a3 recognises the pattern.
    2. For each false positive, identify the over-eager checker and add
       a guard, context filter, or precision improvement.
    3. Propose three new analysis improvements based on the patterns
       observed in the FN list that would have the highest impact on
       detection rate.
    4. Ensure all changes are backward-compatible and do not break
       existing tests (run: python -m pytest tests/).
    """).strip()


# ═══════════════════════════════════════════════════════════════════════════
# JSON dump (for downstream tooling / resumption)
# ═══════════════════════════════════════════════════════════════════════════

def save_json(results: List[BugEvalResult], path: Path) -> None:
    """Persist results as JSON, stripping bulky raw_output."""
    slim = []
    for r in results:
        d = asdict(r)
        # Trim raw output to keep JSON manageable
        for scan_list in ("buggy_scans", "fixed_scans"):
            for scan in d.get(scan_list, []):
                scan["raw_output"] = scan.get("raw_output", "")[:500]
        slim.append(d)
    path.write_text(json.dumps(slim, indent=2, default=str), encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="bugsinpy_eval",
        description="Evaluate a3-python against the BugsInPy benchmark",
    )
    p.add_argument(
        "--projects", nargs="*", default=ALL_PROJECTS,
        help=f"Projects to evaluate (default: all {len(ALL_PROJECTS)})",
    )
    p.add_argument("--limit", type=int, default=0,
                   help="Stop after N bugs (0 = no limit)")
    p.add_argument("--out", type=Path, default=None,
                   help="Markdown report path (default: results/bugsinpy_eval_<ts>.md)")
    p.add_argument("--json-out", type=Path, default=None,
                   help="JSON output path")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args(argv)

    if not BUGS_DIR.exists():
        print(f"ERROR: BugsInPy not found at {BUGS_DIR}", file=sys.stderr)
        print("  git clone https://github.com/soarsmu/BugsInPy.git BugsInPy", file=sys.stderr)
        return 1

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = args.out     or (A3_ROOT / "results" / f"bugsinpy_eval_{ts}.md")
    json_path = args.json_out or out_path.with_suffix(".json")

    print(f"BugsInPy Evaluation — a3-python")
    print(f"Projects : {', '.join(args.projects)}")
    print(f"Limit    : {args.limit or 'all'}")
    print(f"Output   : {out_path}")
    print()

    # Ensure output dirs exist before we start
    out_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)

    results: List[BugEvalResult] = []
    interrupted = False
    try:
        results = run_evaluation(
            args.projects, args.limit, args.verbose,
            json_path=json_path,
        )
    except KeyboardInterrupt:
        # Grab whatever results were collected so far from the
        # incremental JSON (run_evaluation saves after each bug)
        interrupted = True
        print("\n\n[interrupted] Generating report with results so far…")
        if json_path.exists():
            try:
                raw = json.loads(json_path.read_text())
                results = [
                    BugEvalResult(**{k: v for k, v in d.items()
                                     if k in BugEvalResult.__dataclass_fields__})
                    for d in raw
                ]
            except Exception:
                pass  # fall through with whatever we have

    # Always generate the report, even on Ctrl+C
    _finalise(results, out_path, json_path, interrupted)
    return 0


def _finalise(
    results: List[BugEvalResult],
    out_path: Path,
    json_path: Path,
    interrupted: bool = False,
) -> None:
    """Print summary, write report + JSON — called even after Ctrl+C."""
    tp = sum(1 for r in results if r.a3_correct)
    fn = sum(1 for r in results if r.classification == "FALSE_NEGATIVE")
    fp = sum(1 for r in results if r.classification == "FALSE_POSITIVE")
    tag = " (partial — interrupted)" if interrupted else ""
    print(f"\n{'='*60}")
    print(f"  Total: {len(results)}  |  TP: {tp}  |  FN: {fn}  |  FP: {fp}{tag}")
    if tp + fn > 0:
        print(f"  Detection rate: {tp/(tp+fn)*100:.1f}%")
    print(f"{'='*60}")

    generate_report(results, out_path)
    save_json(results, json_path)

    prompts_count = sum(1 for r in results if r.improvement_prompt)
    print(f"\nReport   → {out_path}")
    print(f"JSON     → {json_path}")
    print(f"Prompts  → {prompts_count} improvement prompts generated")


if __name__ == "__main__":
    sys.exit(main())
