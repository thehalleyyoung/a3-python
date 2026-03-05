#!/usr/bin/env python3
"""
A³ Ablation Study
==================

Evaluates four configurations of the A³ analyzer on the BugsInPy benchmark
to measure the contribution of each major subsystem:

  1. **Full A³**              – All features enabled (kitchensink + interprocedural + DSE)
  2. **A³ − Kitchensink**     – No 20-paper portfolio analysis (basic symbolic only)
  3. **A³ − Interprocedural** – No call graph / taint summaries / cross-function tracking
  4. **A³ − DSE**             – No concolic / dynamic symbolic execution

For each BugsInPy bug we extract the buggy and fixed files from the patch,
run each configuration, and classify: TP, FP, FN, BOTH_BUG, etc.

Usage:
    python scripts/ablation_study.py                              # all projects
    python scripts/ablation_study.py --projects keras fastapi     # specific projects
    python scripts/ablation_study.py --limit 50                   # first N bugs
    python scripts/ablation_study.py --out results/ablation.md    # output path
"""

from __future__ import annotations

import argparse
import json
import os
import re
import concurrent.futures
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Paths ───────────────────────────────────────────────────────────────────
A3_ROOT    = Path(__file__).resolve().parent.parent
BUGSINPY   = A3_ROOT / "BugsInPy"
BUGS_DIR   = BUGSINPY / "projects"
CLASSIFIED = A3_ROOT / "results" / "bugsinpy_classified.json"

ALL_PROJECTS = sorted(
    d.name for d in BUGS_DIR.iterdir() if d.is_dir()
) if BUGS_DIR.exists() else []

A3_TIMEOUT = 120  # seconds per file
FILE_CACHE = A3_ROOT / "bugsinpy_workspace" / "file_cache"

# When checking findings, only count those within PATCH_LINE_MARGIN lines
# of an actually-changed line.  This avoids counting unrelated warnings
# elsewhere in a large file.
PATCH_LINE_MARGIN = 10


def _load_in_scope_set() -> set[tuple[str, int]]:
    """Load the set of (project, bug_id) pairs classified as in-scope.

    The classification comes from results/bugsinpy_classified.json which was
    produced by scripts/classify_bugsinpy_scope.py.  A bug is "in-scope" if
    its root cause is a crash, exception, security, or semantic error that a
    static analyser like A³ could plausibly detect (as opposed to pure logic /
    formatting / performance bugs).
    """
    if not CLASSIFIED.exists():
        return set()          # degrade gracefully — treat all as in-scope
    with open(CLASSIFIED) as f:
        entries = json.load(f)
    return {
        (e["project"], int(e["bug_id"]))
        for e in entries
        if e.get("in_scope")
    }

# ── Ablation configurations ─────────────────────────────────────────────────

@dataclass
class AblationConfig:
    """One ablation variant."""
    name: str
    short: str           # Short label for tables
    cli_flags: List[str] # Extra flags to pass to `a3`
    description: str

CONFIGS = [
    AblationConfig(
        name="Full A³",
        short="Full",
        cli_flags=[
            "--functions", "--interprocedural", "--dse-verify",
            "--deduplicate", "--min-confidence", "0.3",
        ],
        description="All features: kitchensink + interprocedural + DSE",
    ),
    AblationConfig(
        name="A³ − Kitchensink",
        short="−KS",
        cli_flags=[
            "--no-kitchensink",
            "--functions", "--interprocedural", "--dse-verify",
            "--deduplicate", "--min-confidence", "0.3",
        ],
        description="No 20-paper portfolio analysis (basic symbolic + BMC only)",
    ),
    AblationConfig(
        name="A³ − Interprocedural",
        short="−IPA",
        cli_flags=[
            "--functions",
            "--deduplicate", "--min-confidence", "0.3",
            # Note: no --interprocedural flag → intraprocedural only
        ],
        description="No call graph / taint summaries / cross-function analysis",
    ),
    AblationConfig(
        name="A³ − DSE",
        short="−DSE",
        cli_flags=[
            "--no-concolic",
            "--functions", "--interprocedural",
            "--deduplicate", "--min-confidence", "0.3",
        ],
        description="No concolic / dynamic symbolic execution (pure static)",
    ),
]


# ── Data models ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    bug_type: str
    line: int
    confidence: float = 0.0
    message: str = ""


@dataclass
class ScanResult:
    file: str
    exit_code: int
    verdict: str  # SAFE | BUG | UNKNOWN | ERROR
    findings: List[Finding] = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None
    duration_sec: float = 0.0


@dataclass
class ConfigResult:
    """Result of one configuration on one BugsInPy bug."""
    config_name: str
    buggy_scans: List[ScanResult] = field(default_factory=list)
    fixed_scans: List[ScanResult] = field(default_factory=list)
    classification: str = "NOT_RUN"
    # TP, FP, FN, BOTH_BUG, BOTH_CLEAN, NO_PATCH, ERROR
    correct: bool = False
    total_time: float = 0.0


@dataclass
class BugAblationResult:
    """Ablation results for one BugsInPy bug across all configs."""
    project: str
    bug_id: int
    in_scope: bool = True       # Whether this bug is in A³'s theoretical scope
    changed_files: List[str] = field(default_factory=list)
    configs: Dict[str, ConfigResult] = field(default_factory=dict)


# ── Changed-line extraction ─────────────────────────────────────────────────

_HUNK_RE = re.compile(r'^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@')

def _extract_changed_lines(
    patch_text: str,
) -> Dict[str, Tuple[set, set]]:
    """Parse a unified diff to find which line numbers were actually changed.

    Returns ``{filepath: (buggy_changed_lines, fixed_changed_lines)}``.
    *buggy_changed_lines* are the line numbers of removed ('-') lines in the
    **old** (buggy) file, and *fixed_changed_lines* are the line numbers of
    added ('+') lines in the **new** (fixed) file.
    """
    result: Dict[str, Tuple[set, set]] = {}
    current_file: Optional[str] = None
    buggy_set: set = set()
    fixed_set: set = set()
    old_lineno = new_lineno = 0

    for raw_line in patch_text.splitlines():
        if raw_line.startswith('diff --git'):
            if current_file is not None:
                result[current_file] = (buggy_set, fixed_set)
            parts = raw_line.split()
            current_file = None
            for p in parts:
                if p.startswith('b/'):
                    current_file = p[2:]
                    break
            buggy_set = set()
            fixed_set = set()
            continue

        m = _HUNK_RE.match(raw_line)
        if m:
            old_lineno = int(m.group('old_start'))
            new_lineno = int(m.group('new_start'))
            continue

        if current_file is None:
            continue
        if raw_line.startswith('---') or raw_line.startswith('+++'):
            continue

        if raw_line.startswith('-'):
            buggy_set.add(old_lineno)
            old_lineno += 1
        elif raw_line.startswith('+'):
            fixed_set.add(new_lineno)
            new_lineno += 1
        elif raw_line.startswith(' '):
            old_lineno += 1
            new_lineno += 1

    if current_file is not None:
        result[current_file] = (buggy_set, fixed_set)

    return result


def _near_changed_lines(findings: List[Finding], changed_lines: set,
                        margin: int = PATCH_LINE_MARGIN) -> List[Finding]:
    """Filter *findings* to only those within *margin* of a changed line.

    If *changed_lines* is empty the patch side has no changes (pure addition
    or pure deletion), so there are **no relevant findings** — return ``[]``.
    """
    if not changed_lines:
        return []  # no changed lines on this side → nothing relevant
    return [
        f for f in findings
        if any(abs(f.line - cl) <= margin for cl in changed_lines)
    ]


# ── Patch extraction (from bugsinpy_eval.py) ────────────────────────────────

def read_info(path: Path) -> Dict[str, str]:
    """Parse a BugsInPy info file into a dict."""
    info = {}
    if not path.exists():
        return info
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            info[key.strip().strip('"')] = val.strip().strip('"')
    return info


def list_bugs(project: str) -> List[int]:
    """Return sorted bug IDs for a project."""
    bugs_path = BUGS_DIR / project / "bugs"
    if not bugs_path.exists():
        return []
    return sorted(
        int(d.name) for d in bugs_path.iterdir()
        if d.is_dir() and d.name.isdigit()
    )


# ── Full-file fetching from GitHub ──────────────────────────────────────────

def _github_raw_url(github_url: str, commit: str, filepath: str) -> str:
    """Construct a raw.githubusercontent.com URL for a file at a commit."""
    parts = github_url.rstrip("/").split("/")
    owner, repo = parts[-2], parts[-1]
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{filepath}"


def _fetch_file_cached(url: str, cache_path: Path) -> Optional[str]:
    """Fetch a file from *url*, returning its text.  Cache locally."""
    if cache_path.exists():
        return cache_path.read_text(errors="replace")
    try:
        req = urllib.request.Request(url)
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            req.add_header("Authorization", f"token {token}")
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(content, encoding="utf-8")
        return content
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return None


def _get_full_source_files(
    project: str, bug_id: int, file_paths: List[str],
) -> Optional[Dict[str, Tuple[str, str]]]:
    """Fetch the *complete* buggy & fixed source files from GitHub.

    Uses the commit hashes in ``bug.info`` and the repo URL in
    ``project.info`` to construct raw-file URLs, with local caching
    so each file is downloaded at most once.

    Returns ``{filepath: (buggy_content, fixed_content)}`` or ``None``
    if any file could not be fetched.
    """
    proj_info = read_info(BUGS_DIR / project / "project.info")
    bug_info  = read_info(BUGS_DIR / project / "bugs" / str(bug_id) / "bug.info")

    github_url   = proj_info.get("github_url", "")
    buggy_commit = bug_info.get("buggy_commit_id", "")
    fixed_commit = bug_info.get("fixed_commit_id", "")

    if not (github_url and buggy_commit and fixed_commit):
        return None

    result: Dict[str, Tuple[str, str]] = {}
    for fpath in file_paths:
        buggy_url = _github_raw_url(github_url, buggy_commit, fpath)
        fixed_url = _github_raw_url(github_url, fixed_commit, fpath)

        buggy_cache = FILE_CACHE / project / buggy_commit[:12] / fpath
        fixed_cache = FILE_CACHE / project / fixed_commit[:12] / fpath

        buggy_src = _fetch_file_cached(buggy_url, buggy_cache)
        fixed_src = _fetch_file_cached(fixed_url, fixed_cache)

        if buggy_src is None or fixed_src is None:
            return None  # partial failure → caller should fall back
        result[fpath] = (buggy_src, fixed_src)

    return result if result else None


# ── Fallback: dedent patch fragments into valid-ish Python ──────────────────

def _dedent_fragment(src: str) -> str:
    """Best-effort repair of a diff-hunk fragment into compilable Python.

    Steps:
      1. textwrap.dedent to strip common leading whitespace
      2. Try compiling as-is
      3. Append ``pass`` for unterminated blocks
      4. Wrap in ``def _fragment():`` if still invalid
    """
    code = textwrap.dedent(src)
    if not code.strip():
        return code

    # Already valid?
    if _compiles(code):
        return code

    # Trailing colon with no body?
    trimmed = code.rstrip()
    attempt = trimmed + "\n    pass\n"
    if _compiles(attempt):
        return attempt

    # Wrap in a function (handles code that starts mid-indentation)
    indented = textwrap.indent(code, "    ")
    wrapped = f"def _fragment():\n{indented}\n"
    if _compiles(wrapped):
        return wrapped

    # Wrap + trailing pass
    wrapped2 = f"def _fragment():\n{textwrap.indent(trimmed, '    ')}\n        pass\n"
    if _compiles(wrapped2):
        return wrapped2

    # Give up — return dedented (A³ will skip / return no findings)
    return code


def _compiles(src: str) -> bool:
    try:
        compile(src, "<fragment>", "exec")
        return True
    except SyntaxError:
        return False


def _parse_patch(patch_text: str) -> Dict[str, Tuple[str, str]]:
    """
    Parse a unified diff into {filename: (buggy_source, fixed_source)}.

    BugsInPy convention: the patch goes from *buggy* (---) to *fixed* (+++).
    We reconstruct both versions from the diff hunks.
    Only keeps .py files that are NOT test files.
    """
    file_diffs: Dict[str, List[str]] = {}
    current_file = None

    for line in patch_text.splitlines(keepends=True):
        if line.startswith("diff --git"):
            # Extract b/path
            parts = line.split()
            for p in parts:
                if p.startswith("b/"):
                    current_file = p[2:].strip()
                    break
            else:
                current_file = None
            if current_file:
                file_diffs.setdefault(current_file, [])
        elif current_file is not None:
            file_diffs[current_file].append(line)

    result = {}
    for fname, diff_lines in file_diffs.items():
        # Skip test files, config files, non-Python
        if not fname.endswith(".py"):
            continue
        base = os.path.basename(fname)
        if base.startswith("test_") or base.startswith("tests_"):
            continue
        if "/test/" in fname or "/tests/" in fname:
            continue

        # Reconstruct buggy (pre) and fixed (post) from diff hunks
        buggy_lines: List[str] = []
        fixed_lines: List[str] = []
        in_hunk = False

        for dl in diff_lines:
            if dl.startswith("@@"):
                in_hunk = True
                continue
            if dl.startswith("---") or dl.startswith("+++"):
                continue
            if dl.startswith("diff --git"):
                in_hunk = False
                continue
            if not in_hunk:
                continue

            if dl.startswith("-"):
                buggy_lines.append(dl[1:])
            elif dl.startswith("+"):
                fixed_lines.append(dl[1:])
            else:
                # Context line (starts with space)
                content = dl[1:] if dl.startswith(" ") else dl
                buggy_lines.append(content)
                fixed_lines.append(content)

        buggy_src = "".join(buggy_lines)
        fixed_src = "".join(fixed_lines)

        if buggy_src.strip() or fixed_src.strip():
            result[fname] = (buggy_src, fixed_src)

    return result


# ── A3 runner ───────────────────────────────────────────────────────────────

def _parse_findings(output: str) -> List[Finding]:
    """Extract bug reports from a3's human-readable stdout."""
    findings: List[Finding] = []
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
                findings.append(Finding(
                    bug_type=bt, line=ln, confidence=conf, message=raw_line.strip(),
                ))
                break
    return findings


def run_a3(filepath: Path, config: AblationConfig, verbose: bool = False) -> ScanResult:
    """Run a3-python on a single file with a specific ablation configuration."""
    t0 = time.monotonic()
    cmd = [sys.executable, "-m", "a3_python", str(filepath)] + config.cli_flags
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
    findings = _parse_findings(raw)

    return ScanResult(
        file=str(filepath), exit_code=exit_code, verdict=verdict,
        findings=findings, raw_output=raw[:4000],
        duration_sec=time.monotonic() - t0,
    )


# ── Classification ──────────────────────────────────────────────────────────

def classify(
    buggy_scans: List[ScanResult],
    fixed_scans: List[ScanResult],
    changed_lines_map: Optional[Dict[str, Tuple[set, set]]] = None,
) -> Tuple[str, bool]:
    """
    Classify a bug evaluation result using **differential** analysis.

    When *changed_lines_map* is provided we:
      1. Filter findings to only those near changed lines.
      2. Collect per-file ``(bug_type, line)`` sets on both sides.
      3. Compare: findings in buggy-only → "detected the bug";
         findings in fixed-only → "false alarm on the fix".

    Returns (classification, is_correct):
        TP           – A³ found ≥1 finding near the patch in the buggy
                       version that is *absent* in the fixed version
        FN           – A³ found nothing relevant in buggy, or everything
                       it found is also in fixed
        FP           – A³ found something new in the fixed version only
        BOTH_BUG     – A³ found relevant findings on both sides, but none
                       are differential (identical finding types on both)
        ERROR        – error on either side
    """
    any_error = any(s.verdict == "ERROR" for s in buggy_scans + fixed_scans)
    if any_error:
        return "ERROR", False

    if changed_lines_map:
        # ── Collect near-patch findings per file ────────────────────────
        buggy_types: set = set()   # (bug_type,) tuples found near patch
        fixed_types: set = set()

        for s in buggy_scans:
            fname = Path(s.file).name
            b_lines: set = set()
            f_lines: set = set()
            for fpath, (bc, fc) in changed_lines_map.items():
                if Path(fpath).name == fname:
                    b_lines = bc; f_lines = fc
                    break
            effective = b_lines or f_lines  # proxy when one side is empty
            for f in _near_changed_lines(s.findings, effective):
                buggy_types.add(f.bug_type)

        for s in fixed_scans:
            fname = Path(s.file).name
            b_lines = set(); f_lines = set()
            for fpath, (bc, fc) in changed_lines_map.items():
                if Path(fpath).name == fname:
                    b_lines = bc; f_lines = fc
                    break
            effective = f_lines or b_lines
            for f in _near_changed_lines(s.findings, effective):
                fixed_types.add(f.bug_type)

        # ── Differential comparison ─────────────────────────────────────
        buggy_only = buggy_types - fixed_types     # detected & fixed
        fixed_only = fixed_types - buggy_types     # new in fix (FP)
        shared     = buggy_types & fixed_types     # same in both

        if buggy_only:
            # A³ found something near the bug that disappears in the fix
            return "TRUE_POSITIVE", True
        if fixed_only and not buggy_types:
            # A³ finds issues only in the fixed code
            return "FALSE_POSITIVE", False
        if shared and not buggy_only:
            # Findings exist near the patch on both sides (same types)
            return "BOTH_BUG", False
        # Nothing near the patch
        return "FALSE_NEGATIVE", False

    else:
        # No line info — fall back to raw verdict
        any_buggy = any(s.verdict == "BUG" for s in buggy_scans)
        any_fixed = any(s.verdict == "BUG" for s in fixed_scans)
        if any_buggy and not any_fixed:
            return "TRUE_POSITIVE", True
        if any_buggy and any_fixed:
            return "BOTH_BUG", False
        if not any_buggy and any_fixed:
            return "FALSE_POSITIVE", False
        return "FALSE_NEGATIVE", False


# ── Main evaluation loop ────────────────────────────────────────────────────

def evaluate_bug(project: str, bug_id: int, configs: List[AblationConfig],
                 verbose: bool = False,
                 in_scope_set: Optional[set] = None,
                 fetch: bool = True) -> BugAblationResult:
    """Evaluate all ablation configs on one BugsInPy bug."""
    bug_dir = BUGS_DIR / project / "bugs" / str(bug_id)
    is_in_scope = (in_scope_set is None) or ((project, bug_id) in in_scope_set)

    result = BugAblationResult(project=project, bug_id=bug_id, in_scope=is_in_scope)

    # Read patch
    patch_path = bug_dir / "bug_patch.txt"
    if not patch_path.exists():
        for cfg in configs:
            cr = ConfigResult(config_name=cfg.name, classification="NO_PATCH")
            result.configs[cfg.name] = cr
        return result

    patch_text = patch_path.read_text(errors="replace")
    file_versions = _parse_patch(patch_text)
    if not file_versions:
        for cfg in configs:
            cr = ConfigResult(config_name=cfg.name, classification="NO_PATCH")
            result.configs[cfg.name] = cr
        return result

    result.changed_files = list(file_versions.keys())

    # ── Extract changed line numbers from the patch ──────────────────────
    changed_lines_map = _extract_changed_lines(patch_text)

    # ── Try to obtain FULL source files from GitHub (cached) ────────────
    full_files = None
    if fetch:
        full_files = _get_full_source_files(
            project, bug_id, list(file_versions.keys()),
        )
    if full_files:
        source_files = full_files
    else:
        # Fallback: dedent the patch fragments into valid-ish Python
        source_files = {
            fname: (_dedent_fragment(buggy), _dedent_fragment(fixed))
            for fname, (buggy, fixed) in file_versions.items()
        }

    # Write extracted files
    with tempfile.TemporaryDirectory(prefix="a3_ablation_") as tmpdir:
        tmp = Path(tmpdir)
        buggy_dir = tmp / "buggy"
        fixed_dir = tmp / "fixed"
        buggy_dir.mkdir()
        fixed_dir.mkdir()

        for fname, (buggy_src, fixed_src) in source_files.items():
            bp = buggy_dir / fname
            fp = fixed_dir / fname
            bp.parent.mkdir(parents=True, exist_ok=True)
            fp.parent.mkdir(parents=True, exist_ok=True)
            bp.write_text(buggy_src, encoding="utf-8")
            fp.write_text(fixed_src, encoding="utf-8")

        # Run all configurations in PARALLEL (one thread per config)
        def _run_one_config(cfg: AblationConfig) -> ConfigResult:
            t0 = time.monotonic()
            cr = ConfigResult(config_name=cfg.name)
            for fname in source_files:
                sr = run_a3(buggy_dir / fname, cfg, verbose=verbose)
                cr.buggy_scans.append(sr)
            for fname in source_files:
                sr = run_a3(fixed_dir / fname, cfg, verbose=verbose)
                cr.fixed_scans.append(sr)
            cr.classification, cr.correct = classify(
                cr.buggy_scans, cr.fixed_scans, changed_lines_map,
            )
            cr.total_time = time.monotonic() - t0
            return cr

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(configs)) as pool:
            futures = {pool.submit(_run_one_config, cfg): cfg for cfg in configs}
            for fut in concurrent.futures.as_completed(futures):
                cr = fut.result()
                result.configs[cr.config_name] = cr

    return result


def _load_json(path: Path, configs: List[AblationConfig]) -> List[BugAblationResult]:
    """Load previously-saved JSON results for resume."""
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    results: List[BugAblationResult] = []
    for entry in data:
        ev = BugAblationResult(project=entry["project"], bug_id=entry["bug_id"])
        ev.in_scope = entry.get("in_scope", True)
        ev.changed_files = entry.get("changed_files", [])
        for cfg_name, cdata in entry.get("configs", {}).items():
            cr = ConfigResult(config_name=cfg_name)
            cr.classification = cdata["classification"]
            cr.correct = cdata["correct"]
            cr.total_time = cdata.get("total_time", 0)
            # We don't reconstruct full scans but that's fine for reporting
            ev.configs[cfg_name] = cr
        results.append(ev)
    return results


def run_ablation(
    projects: List[str],
    configs: List[AblationConfig],
    limit: int = 0,
    verbose: bool = False,
    json_path: Optional[Path] = None,
    in_scope_only: bool = True,
    resume: bool = False,
    fetch: bool = True,
) -> List[BugAblationResult]:
    """Run ablation on all requested bugs.

    If *in_scope_only* is True (default), only evaluate bugs that are within
    A³'s theoretical scope (crash / security / semantic errors).  Out-of-scope
    bugs (pure logic, formatting, etc.) are skipped.

    If *resume* is True, load existing results from *json_path* and skip bugs
    that were already evaluated.
    """
    in_scope_set = _load_in_scope_set()

    # Resume: load existing results and build done-set
    results: List[BugAblationResult] = []
    done: set = set()
    if resume and json_path:
        results = _load_json(json_path, configs)
        done = {(ev.project, ev.bug_id) for ev in results}
        if done:
            print(f"  Resuming: {len(done)} bugs already evaluated, skipping them.")

    count = len(results)
    skipped = 0

    for project in projects:
        bug_ids = list_bugs(project)
        for bug_id in bug_ids:
            if in_scope_only and in_scope_set and (project, bug_id) not in in_scope_set:
                skipped += 1
                continue
            if (project, bug_id) in done:
                continue
            if limit and count >= limit:
                if skipped:
                    print(f"  (skipped {skipped} out-of-scope bugs)")
                return results
            count += 1
            label = f"[{count}] {project}/bug#{bug_id}"
            print(f"  {label} …", flush=True)

            ev = evaluate_bug(project, bug_id, configs, verbose=verbose,
                              in_scope_set=in_scope_set, fetch=fetch)
            results.append(ev)

            # Print one-liner per config
            for cfg in configs:
                cr = ev.configs.get(cfg.name)
                if cr:
                    mark = "✓" if cr.correct else "✗"
                    print(f"    {mark} {cfg.short:>6s}  {cr.classification:18s}  ({cr.total_time:.1f}s)")

            # Incremental save
            if json_path:
                _save_json(results, json_path)

    if skipped:
        print(f"  (skipped {skipped} out-of-scope bugs)")
    return results


# ── Report generation ───────────────────────────────────────────────────────

def generate_report(results: List[BugAblationResult], configs: List[AblationConfig]) -> str:
    """Generate a Markdown ablation report."""
    lines: List[str] = []

    lines.append("# A³ Ablation Study")
    lines.append(f"_Generated: {datetime.now().isoformat(timespec='seconds')}_\n")

    # ── Configuration descriptions ──────────────────────────────────────
    lines.append("## Configurations\n")
    lines.append("| Config | Description |")
    lines.append("|--------|-------------|")
    for cfg in configs:
        lines.append(f"| **{cfg.name}** | {cfg.description} |")
    lines.append("")

    # ── Partition results ────────────────────────────────────────────────
    in_scope_results = [ev for ev in results if ev.in_scope]
    oos_results = [ev for ev in results if not ev.in_scope]

    # Helper: emit an aggregate + derived metrics block for a result subset
    def _metrics_block(subset: List[BugAblationResult], heading: str):
        stats: Dict[str, Counter] = {cfg.name: Counter() for cfg in configs}
        cfg_times: Dict[str, List[float]] = {cfg.name: [] for cfg in configs}
        for ev in subset:
            for cfg in configs:
                cr = ev.configs.get(cfg.name)
                if cr:
                    stats[cfg.name][cr.classification] += 1
                    cfg_times[cfg.name].append(cr.total_time)
        n = len(subset)

        lines.append(f"## {heading} — Aggregate Results (n={n})\n")
        lines.append("| Metric | " + " | ".join(cfg.short for cfg in configs) + " |")
        lines.append("|--------" + "|-------" * len(configs) + "|")
        for metric_name in ["TRUE_POSITIVE", "FALSE_NEGATIVE", "FALSE_POSITIVE", "BOTH_BUG", "NO_PATCH", "ERROR"]:
            row = f"| {metric_name} "
            for cfg in configs:
                row += f"| {stats[cfg.name].get(metric_name, 0)} "
            row += "|"
            lines.append(row)
        lines.append(f"| **Total** | " + " | ".join(str(n) for _ in configs) + " |")
        lines.append("")

        lines.append(f"### {heading} — Detection Metrics\n")
        lines.append("| Metric | " + " | ".join(cfg.short for cfg in configs) + " |")
        lines.append("|--------" + "|-------" * len(configs) + "|")
        for metric_label, compute_fn in [
            ("Detection Rate (TP / (TP+FN+BOTH))", lambda s: _pct(s["TRUE_POSITIVE"], s["TRUE_POSITIVE"] + s["FALSE_NEGATIVE"] + s["BOTH_BUG"])),
            ("Precision (TP / (TP+FP+BOTH))", lambda s: _pct(s["TRUE_POSITIVE"], s["TRUE_POSITIVE"] + s["FALSE_POSITIVE"] + s["BOTH_BUG"])),
            ("F1 Score", lambda s: _f1(s["TRUE_POSITIVE"], s["FALSE_POSITIVE"] + s["BOTH_BUG"], s["FALSE_NEGATIVE"])),
            ("Avg Time (s)", lambda s: None),
        ]:
            row = f"| {metric_label} "
            for cfg in configs:
                s = stats[cfg.name]
                if metric_label.startswith("Avg Time"):
                    t = cfg_times[cfg.name]
                    val = f"{sum(t)/max(len(t),1):.1f}s" if t else "—"
                else:
                    val = compute_fn(s)
                row += f"| {val} "
            row += "|"
            lines.append(row)
        lines.append("")

    _metrics_block(in_scope_results, "In-Scope Bugs")
    if oos_results:
        _metrics_block(oos_results, "Out-of-Scope Bugs")
    _metrics_block(results, "All Bugs (combined)")

    # ── Per-project breakdown ───────────────────────────────────────────
    projects = sorted(set(ev.project for ev in results))
    if len(projects) > 1:
        lines.append("## Per-Project Detection Rate (in-scope only)\n")
        lines.append("| Project | In-scope | " + " | ".join(cfg.short for cfg in configs) + " |")
        lines.append("|---------|---------" + "|-------" * len(configs) + "|")

        for proj in projects:
            proj_evs = [ev for ev in in_scope_results if ev.project == proj]
            if not proj_evs:
                continue
            row = f"| {proj} | {len(proj_evs)} "
            for cfg in configs:
                tp = sum(1 for ev in proj_evs if ev.configs.get(cfg.name, ConfigResult(config_name="")).classification == "TRUE_POSITIVE")
                evaluable = sum(1 for ev in proj_evs if ev.configs.get(cfg.name, ConfigResult(config_name="")).classification not in ("NO_PATCH", "ERROR"))
                row += f"| {_pct(tp, evaluable)} ({tp}/{evaluable}) "
            row += "|"
            lines.append(row)
        lines.append("")

    # ── Diff analysis: where configs disagree ───────────────────────────
    lines.append("## Configuration Disagreements (in-scope)\n")
    lines.append("Cases where at least one config differs from the others:\n")
    lines.append("| # | Project | Bug | " + " | ".join(cfg.short for cfg in configs) + " |")
    lines.append("|---|---------|-----" + "|------" * len(configs) + "|")

    diff_count = 0
    for ev in in_scope_results:
        classifications = [ev.configs.get(cfg.name, ConfigResult(config_name="")).classification for cfg in configs]
        if len(set(classifications)) > 1:
            diff_count += 1
            row = f"| {diff_count} | {ev.project} | {ev.bug_id} "
            for cfg in configs:
                cr = ev.configs.get(cfg.name)
                cls = cr.classification if cr else "—"
                marker = "✓" if (cr and cr.correct) else "✗" if cr else "—"
                row += f"| {marker} {cls} "
            row += "|"
            lines.append(row)

    if diff_count == 0:
        lines.append("| — | — | — | " + " | ".join("(all same)" for _ in configs) + " |")
    lines.append(f"\n**{diff_count} disagreements** out of {len(in_scope_results)} in-scope bugs.\n")

    # ── Delta analysis: what each ablation loses ────────────────────────
    lines.append("## Ablation Delta Analysis (in-scope)\n")
    lines.append("Bugs that **Full A³** gets right but an ablated config misses:\n")

    full_name = configs[0].name
    for cfg in configs[1:]:
        lost = []
        gained = []
        for ev in in_scope_results:
            full_cr = ev.configs.get(full_name)
            abl_cr = ev.configs.get(cfg.name)
            if full_cr and abl_cr:
                if full_cr.correct and not abl_cr.correct:
                    lost.append(f"{ev.project}/bug#{ev.bug_id}")
                elif not full_cr.correct and abl_cr.correct:
                    gained.append(f"{ev.project}/bug#{ev.bug_id}")

        lines.append(f"### {cfg.name}\n")
        lines.append(f"- **Lost** (Full correct, ablated wrong): **{len(lost)}**")
        if lost:
            for b in lost[:20]:
                lines.append(f"  - {b}")
            if len(lost) > 20:
                lines.append(f"  - ... and {len(lost)-20} more")
        lines.append(f"- **Gained** (ablated correct, Full wrong): **{len(gained)}**")
        if gained:
            for b in gained[:20]:
                lines.append(f"  - {b}")
        lines.append("")

    # ── Timing comparison ───────────────────────────────────────────────
    lines.append("## Timing Comparison\n")
    lines.append("| Config | Total (s) | Mean (s) | Median (s) | Max (s) |")
    lines.append("|--------|-----------|----------|------------|---------|")
    for cfg in configs:
        t = sorted(
            cr.total_time
            for ev in in_scope_results
            for cr in [ev.configs.get(cfg.name)]
            if cr
        )
        if t:
            total_t = sum(t)
            mean_t = total_t / len(t)
            median_t = t[len(t) // 2]
            max_t = t[-1]
            lines.append(f"| {cfg.short} | {total_t:.1f} | {mean_t:.1f} | {median_t:.1f} | {max_t:.1f} |")
        else:
            lines.append(f"| {cfg.short} | — | — | — | — |")
    lines.append("")

    # ── Per-bug detail table ────────────────────────────────────────────
    lines.append("## Per-Bug Detail (in-scope)\n")
    lines.append("| # | Project | Bug | " + " | ".join(cfg.short for cfg in configs) + " |")
    lines.append("|---|---------|-----" + "|------" * len(configs) + "|")

    for i, ev in enumerate(in_scope_results, 1):
        row = f"| {i} | {ev.project} | {ev.bug_id} "
        for cfg in configs:
            cr = ev.configs.get(cfg.name)
            if cr:
                marker = "✓" if cr.correct else "✗"
                row += f"| {marker} {cr.classification[:6]} "
            else:
                row += "| — "
        row += "|"
        lines.append(row)
    lines.append("")

    return "\n".join(lines)


def _pct(num: int, denom: int) -> str:
    if denom == 0:
        return "—"
    return f"{num/denom*100:.1f}%"


def _f1(tp: int, fp: int, fn: int) -> str:
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    if prec + rec == 0:
        return "0.0%"
    f1 = 2 * prec * rec / (prec + rec)
    return f"{f1*100:.1f}%"


def _save_json(results: List[BugAblationResult], path: Path):
    """Save results incrementally to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)

    serializable = []
    for ev in results:
        entry = {
            "project": ev.project,
            "bug_id": ev.bug_id,
            "in_scope": ev.in_scope,
            "changed_files": ev.changed_files,
            "configs": {},
        }
        for cfg_name, cr in ev.configs.items():
            entry["configs"][cfg_name] = {
                "classification": cr.classification,
                "correct": cr.correct,
                "total_time": cr.total_time,
                "buggy_verdicts": [s.verdict for s in cr.buggy_scans],
                "fixed_verdicts": [s.verdict for s in cr.fixed_scans],
                "buggy_findings": [
                    {"bug_type": f.bug_type, "line": f.line}
                    for s in cr.buggy_scans for f in s.findings
                ],
                "fixed_findings": [
                    {"bug_type": f.bug_type, "line": f.line}
                    for s in cr.fixed_scans for f in s.findings
                ],
            }
        serializable.append(entry)

    with open(path, "w") as f:
        json.dump(serializable, f, indent=2)


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="A³ Ablation Study — measure contribution of each subsystem",
    )
    parser.add_argument(
        "--projects", nargs="*", default=None,
        help=f"Projects to evaluate (default: all). Available: {', '.join(ALL_PROJECTS)}",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Max number of bugs to evaluate (0=all)",
    )
    parser.add_argument(
        "--out", type=Path, default=Path("results/ablation_study.md"),
        help="Output Markdown report path",
    )
    parser.add_argument(
        "--json", type=Path, default=Path("results/ablation_study.json"),
        help="Output JSON results path (for incremental save)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print a3 output for each scan",
    )
    parser.add_argument(
        "--configs", nargs="*", default=None,
        choices=["full", "no-ks", "no-ipa", "no-dse"],
        help="Run only specific configs (default: all four)",
    )
    parser.add_argument(
        "--all-bugs", action="store_true",
        help="Include ALL BugsInPy bugs, not just those in A³'s scope (crash/security/semantic)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from existing JSON results (skip already-evaluated bugs)",
    )
    parser.add_argument(
        "--no-fetch", action="store_true",
        help="Do not fetch full source files from GitHub (use patch fragments only)",
    )
    args = parser.parse_args()

    projects = args.projects or ALL_PROJECTS
    missing = [p for p in projects if p not in ALL_PROJECTS]
    if missing:
        print(f"Warning: projects not found in BugsInPy: {missing}", file=sys.stderr)
        projects = [p for p in projects if p in ALL_PROJECTS]

    if not projects:
        print("No projects to evaluate. Check BugsInPy directory.", file=sys.stderr)
        sys.exit(1)

    # Filter configs if requested
    config_map = {"full": 0, "no-ks": 1, "no-ipa": 2, "no-dse": 3}
    if args.configs:
        selected = [CONFIGS[config_map[c]] for c in args.configs]
    else:
        selected = list(CONFIGS)

    print("=" * 70)
    print("  A³ ABLATION STUDY")
    print("=" * 70)
    print(f"  Projects:  {', '.join(projects)}")
    print(f"  Configs:   {', '.join(c.name for c in selected)}")
    print(f"  Scope:     {'all bugs' if args.all_bugs else 'in-scope only (250/501)'}")
    print(f"  Sources:   {'patch fragments only' if args.no_fetch else 'full files from GitHub (cached)'}")
    print(f"  Limit:     {args.limit or 'all'}")
    print(f"  Output:    {args.out}")
    print("=" * 70)
    print()

    results = run_ablation(
        projects=projects,
        configs=selected,
        limit=args.limit,
        verbose=args.verbose,
        json_path=args.json,
        in_scope_only=not args.all_bugs,
        resume=args.resume,
        fetch=not args.no_fetch,
    )

    # Generate and save report
    report = generate_report(results, selected)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report)
    print(f"\n{'='*70}")
    print(f"  Report saved to {args.out}")
    print(f"  JSON saved to {args.json}")
    print(f"{'='*70}")

    # Print summary
    in_scope = [ev for ev in results if ev.in_scope]
    print(f"\nQuick Summary (in-scope: {len(in_scope)}, total: {len(results)}):")
    for cfg in selected:
        tp = sum(1 for ev in in_scope if ev.configs.get(cfg.name, ConfigResult(config_name="")).correct)
        evaluable = sum(1 for ev in in_scope if ev.configs.get(cfg.name, ConfigResult(config_name="")).classification not in ("NO_PATCH", "ERROR"))
        print(f"  {cfg.name:25s}  TP={tp}/{evaluable}  ({_pct(tp, evaluable)})")


if __name__ == "__main__":
    main()
