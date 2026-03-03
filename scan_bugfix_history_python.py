#!/usr/bin/env python3
"""
Bugfix-Driven Improvement Pipeline for a3-python using BugsInPy.

Uses the BugsInPy benchmark (17 real-world Python projects with curated bugs)
as ground truth. For each bug, checks out the buggy and fixed commits,
scans with a3-python, classifies false positives / false negatives,
and iteratively invokes copilot-cli to improve a3's detectors.

Iterative loop:
  1. SCAN  — Checkout BugsInPy buggy/fixed commits, scan with a3-python
  2. DIAGNOSE — Classify FP/FN, identify pathological detector gaps
  3. IMPROVE — Feed targeted fix prompts to copilot CLI, re-scan to verify
  4. LOOP  — Re-scans to measure improvement; stops on plateau or max iterations

Usage:
    python3 scan_bugfix_history_python.py                          # Full pipeline (default 5 iters)
    python3 scan_bugfix_history_python.py --max-iterations 10      # More iterations
    python3 scan_bugfix_history_python.py --scan-only              # Phase 1+2 only (no improvements)
    python3 scan_bugfix_history_python.py --project keras           # Single BugsInPy project
    python3 scan_bugfix_history_python.py --max-bugs 20             # Limit bugs per project
    python3 scan_bugfix_history_python.py --dry-run                 # Print prompts, don't execute
    python3 scan_bugfix_history_python.py --resume                  # Resume from last checkpoint
    python3 scan_bugfix_history_python.py --repo-url https://github.com/pallets/flask  # Ad-hoc repo
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
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── paths ──────────────────────────────────────────────────────────────────────
WORKSPACE = Path(__file__).parent.absolute()
BUGSINPY_REPO = "https://github.com/soarsmu/BugsInPy.git"
BUGSINPY_DIR = WORKSPACE / "BugsInPy"
CHECKOUT_DIR = WORKSPACE / "bugsinpy_workspace"
RESULTS_DIR = WORKSPACE / "results" / "bugfix_scan_python"
STATE_FILE = RESULTS_DIR / "pipeline_state.json"
LOG_FILE = WORKSPACE / "bugfix_scan_python.log"
TEST_REPOS = WORKSPACE / "test_repos_python"

# All 17 BugsInPy projects
PROJECTS = [
    "PySnooper", "ansible", "black", "cookiecutter", "fastapi",
    "httpie", "keras", "luigi", "matplotlib", "pandas",
    "sanic", "scrapy", "spacy", "thefuck", "tornado",
    "tqdm", "youtube-dl",
]

# Maps a3-python bug types → detector source files
DETECTOR_FILE_MAP = {
    "ASSERT_FAIL": "a3_python/unsafe/assert_fail.py",
    "DIV_ZERO": "a3_python/unsafe/div_zero.py",
    "FP_DOMAIN": "a3_python/unsafe/fp_domain.py",
    "INTEGER_OVERFLOW": "a3_python/unsafe/integer_overflow.py",
    "BOUNDS": "a3_python/unsafe/bounds.py",
    "NULL_PTR": "a3_python/unsafe/null_ptr.py",
    "TYPE_CONFUSION": "a3_python/unsafe/type_confusion.py",
    "STACK_OVERFLOW": "a3_python/unsafe/stack_overflow.py",
    "MEMORY_LEAK": "a3_python/unsafe/memory_leak.py",
    "NON_TERMINATION": "a3_python/unsafe/non_termination.py",
    "ITERATOR_INVALID": "a3_python/unsafe/iterator_invalid.py",
    "USE_AFTER_FREE": "a3_python/unsafe/use_after_free.py",
    "DOUBLE_FREE": "a3_python/unsafe/double_free.py",
    "UNINIT_MEMORY": "a3_python/unsafe/uninit_memory.py",
    "DATA_RACE": "a3_python/unsafe/data_race.py",
    "DEADLOCK": "a3_python/unsafe/deadlock.py",
    "SEND_SYNC": "a3_python/unsafe/send_sync.py",
    "INFO_LEAK": "a3_python/unsafe/info_leak.py",
    "TIMING_CHANNEL": "a3_python/unsafe/timing_channel.py",
    "PANIC": "a3_python/unsafe/panic.py",
    "SQL_INJECTION": "a3_python/unsafe/security/sql_injection.py",
    "COMMAND_INJECTION": "a3_python/unsafe/security/command_injection.py",
    "CODE_INJECTION": "a3_python/unsafe/security/code_injection.py",
    "PATH_INJECTION": "a3_python/unsafe/security/path_injection.py",
    "REFLECTED_XSS": "a3_python/unsafe/security/xss.py",
    "SSRF": "a3_python/unsafe/security/ssrf.py",
    "UNSAFE_DESERIALIZATION": "a3_python/unsafe/security/deserialization.py",
    "XXE": "a3_python/unsafe/security/xxe.py",
    "CLEARTEXT_LOGGING": "a3_python/unsafe/security/cleartext.py",
    "CLEARTEXT_STORAGE": "a3_python/unsafe/security/cleartext.py",
}

# Maps commit/patch keywords → a3-python bug types for classification
BUG_KEYWORD_MAP = {
    "overflow": "INTEGER_OVERFLOW", "underflow": "INTEGER_OVERFLOW",
    "indexerror": "BOUNDS", "index error": "BOUNDS",
    "out of bounds": "BOUNDS", "out-of-bounds": "BOUNDS",
    "keyerror": "BOUNDS", "key error": "BOUNDS",
    "typeerror": "TYPE_CONFUSION", "type error": "TYPE_CONFUSION",
    "valueerror": "ASSERT_FAIL", "value error": "ASSERT_FAIL",
    "assertionerror": "ASSERT_FAIL", "assertion": "ASSERT_FAIL",
    "zerodivisionerror": "DIV_ZERO", "division by zero": "DIV_ZERO",
    "divide by zero": "DIV_ZERO",
    "attributeerror": "NULL_PTR", "attribute error": "NULL_PTR",
    "nonetype": "NULL_PTR", "null": "NULL_PTR",
    "recursionerror": "STACK_OVERFLOW", "recursion": "STACK_OVERFLOW",
    "stack overflow": "STACK_OVERFLOW",
    "memoryerror": "MEMORY_LEAK", "memory leak": "MEMORY_LEAK", "leak": "MEMORY_LEAK",
    "race": "DATA_RACE", "data race": "DATA_RACE",
    "deadlock": "DEADLOCK",
    "infinite loop": "NON_TERMINATION", "hang": "NON_TERMINATION",
    "sql injection": "SQL_INJECTION", "sqli": "SQL_INJECTION",
    "command injection": "COMMAND_INJECTION",
    "xss": "REFLECTED_XSS", "cross-site": "REFLECTED_XSS",
    "deserialization": "UNSAFE_DESERIALIZATION", "pickle": "UNSAFE_DESERIALIZATION",
    "xxe": "XXE",
}

PLATEAU_THRESHOLD = 0.02
PLATEAU_PATIENCE = 2
DEFAULT_MAX_ITERS = 5
MAX_FIX_RETRIES = 3
A3_SCAN_TIMEOUT = 120
COPILOT_TIMEOUT = 900

SKIP_DIRS = {
    "__pycache__", ".git", "venv", ".venv", "node_modules",
    ".egg-info", "dist", "build", ".tox", ".mypy_cache",
    "tests", "test", "testing", "docs", "doc", "examples",
    "benchmarks", "scripts",
}


# ── logging ────────────────────────────────────────────────────────────────────
def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def log_phase(phase: str, iteration: int):
    print(f"\n{'='*70}")
    print(f"  ITERATION {iteration} — PHASE: {phase}")
    print(f"{'='*70}\n")


# ── BugsInPy helpers ───────────────────────────────────────────────────────────
def ensure_bugsinpy_cloned() -> None:
    """Clone BugsInPy if not already present."""
    if BUGSINPY_DIR.exists():
        log(f"BugsInPy already at {BUGSINPY_DIR}")
        return
    log(f"Cloning BugsInPy to {BUGSINPY_DIR} ...")
    subprocess.run(
        ["git", "clone", "--depth=1", BUGSINPY_REPO, str(BUGSINPY_DIR)],
        check=True, timeout=120,
    )
    log("BugsInPy cloned.")


def list_bugs(project: str) -> list[int]:
    """Return sorted list of bug IDs for a BugsInPy project."""
    bugs_dir = BUGSINPY_DIR / "projects" / project / "bugs"
    if not bugs_dir.exists():
        return []
    return sorted(int(d.name) for d in bugs_dir.iterdir()
                  if d.is_dir() and d.name.isdigit())


def get_bug_info(project: str, bug_id: int) -> dict:
    """Parse bug.info for a specific bug."""
    info_file = BUGSINPY_DIR / "projects" / project / "bugs" / str(bug_id) / "bug.info"
    info = {}
    if info_file.exists():
        for line in info_file.read_text().splitlines():
            line = line.strip()
            if "=" in line:
                key, _, val = line.partition("=")
                info[key.strip()] = val.strip().strip('"')
    return info


def get_project_info(project: str) -> dict:
    """Parse project.info for a BugsInPy project."""
    info_file = BUGSINPY_DIR / "projects" / project / "project.info"
    info = {}
    if info_file.exists():
        for line in info_file.read_text().splitlines():
            line = line.strip()
            if "=" in line:
                key, _, val = line.partition("=")
                info[key.strip()] = val.strip().strip('"')
    return info


def get_patch_files(project: str, bug_id: int) -> list[str]:
    """Extract changed source file paths from bug_patch.txt."""
    patch_file = BUGSINPY_DIR / "projects" / project / "bugs" / str(bug_id) / "bug_patch.txt"
    if not patch_file.exists():
        return []
    changed = []
    for line in patch_file.read_text().splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                path = parts[3].lstrip("b/")
                if path.endswith(".py") and not path.startswith("test"):
                    changed.append(path)
        elif line.startswith("+++ b/"):
            path = line[6:]
            if path.endswith(".py") and not path.startswith("test"):
                changed.append(path)
    seen = set()
    result = []
    for p in changed:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def get_patch_context(project: str, bug_id: int) -> str:
    """Return raw patch text for context in prompts."""
    patch_file = BUGSINPY_DIR / "projects" / project / "bugs" / str(bug_id) / "bug_patch.txt"
    if patch_file.exists():
        return patch_file.read_text()[:3000]
    return ""


def checkout_bug(project: str, bug_id: int, buggy: bool = True) -> Path:
    """Checkout a BugsInPy bug (buggy or fixed version) into workspace."""
    bug_info = get_bug_info(project, bug_id)
    project_info = get_project_info(project)
    github_url = project_info.get("github_url", "")
    if not github_url:
        raise ValueError(f"No github_url for project {project}")

    commit_id = bug_info.get("buggy_commit_id" if buggy else "fixed_commit_id", "")
    if not commit_id:
        raise ValueError(f"No {'buggy' if buggy else 'fixed'}_commit_id for {project} bug {bug_id}")

    version_label = "buggy" if buggy else "fixed"
    checkout_dir = CHECKOUT_DIR / f"{project}_bug{bug_id}_{version_label}"

    if checkout_dir.exists():
        shutil.rmtree(checkout_dir)

    checkout_dir.mkdir(parents=True, exist_ok=True)
    log(f"  Cloning {project} at {version_label} commit {commit_id[:8]}...")

    try:
        subprocess.run(
            ["git", "clone", "--depth=50", github_url, str(checkout_dir)],
            check=True, capture_output=True, timeout=120,
        )
        subprocess.run(
            ["git", "-C", str(checkout_dir), "fetch", "--depth=50", "origin", commit_id],
            capture_output=True, timeout=60,
        )
        subprocess.run(
            ["git", "-C", str(checkout_dir), "checkout", commit_id],
            check=True, capture_output=True, timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log(f"  WARNING: Could not checkout {project} bug {bug_id}: {e}", "WARN")
        if checkout_dir.exists():
            shutil.rmtree(checkout_dir)
        raise

    return checkout_dir


def cleanup_checkout(checkout_dir: Path) -> None:
    """Remove a checked-out project directory."""
    if checkout_dir.exists():
        shutil.rmtree(checkout_dir, ignore_errors=True)


def find_python_files(directory: Path, max_files: int = 20,
                      priority_files: list[str] | None = None) -> list[Path]:
    """Find Python source files, prioritizing patch-affected files."""
    py_files: list[Path] = []
    priority_set: set[Path] = set()
    if priority_files:
        for rel in priority_files:
            p = directory / rel
            if p.exists() and p.suffix == ".py":
                py_files.append(p)
                priority_set.add(p.resolve())
        if len(py_files) >= max_files:
            return py_files[:max_files]

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for f in sorted(files):
            if (f.endswith(".py") and not f.startswith("test_")
                    and f != "setup.py" and f != "conftest.py"):
                candidate = Path(root) / f
                if candidate.resolve() not in priority_set:
                    py_files.append(candidate)
                    if len(py_files) >= max_files:
                        return py_files
    return py_files


# ── a3-python scanning ────────────────────────────────────────────────────────
def scan_file_with_a3(filepath: Path) -> dict:
    """Scan a single Python file with a3. Returns structured results."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "a3_python", str(filepath),
             "--no-intent-filter", "--min-confidence", "0.3"],
            capture_output=True, text=True,
            timeout=A3_SCAN_TIMEOUT, cwd=str(WORKSPACE),
        )
        exit_code = result.returncode
        stdout = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return {"exit_code": 3, "stdout": "TIMEOUT", "bugs_found": [], "verdict": "ERROR"}
    except Exception as e:
        return {"exit_code": 3, "stdout": str(e), "bugs_found": [], "verdict": "ERROR"}

    bugs_found = []
    for line in stdout.splitlines():
        if any(kw in line.upper() for kw in ["BUG:", "VULNERABILITY:", "FINDING:", "⚠"]):
            bugs_found.append(line.strip())

    verdict_map = {0: "SAFE", 1: "BUG", 2: "UNKNOWN"}
    verdict = verdict_map.get(exit_code, "ERROR")
    return {"exit_code": exit_code, "stdout": stdout, "bugs_found": bugs_found, "verdict": verdict}


def scan_files_aggregate(py_files: list[Path]) -> dict:
    """Scan multiple files and aggregate results."""
    results = [scan_file_with_a3(pf) for pf in py_files]
    if not results:
        return {"exit_code": 0, "stdout": "", "bugs_found": [], "verdict": "SAFE"}
    return {
        "exit_code": max(r["exit_code"] for r in results),
        "stdout": "\n---\n".join(r["stdout"] for r in results)[:4000],
        "bugs_found": [b for r in results for b in r["bugs_found"]],
        "verdict": (
            "BUG" if any(r["verdict"] == "BUG" for r in results) else
            "UNKNOWN" if any(r["verdict"] in ("UNKNOWN", "ERROR") for r in results) else
            "SAFE"
        ),
    }


# ── FP/FN classification ──────────────────────────────────────────────────────
def classify_bugsinpy_result(
    project: str, bug_id: int,
    buggy_result: dict, fixed_result: dict,
    bug_info: dict,
) -> dict | None:
    """
    Compare scan results for buggy vs fixed commits to detect FP/FN.

    Ground truth:
      - Buggy commit has a real bug → a3 should report BUG (else FN)
      - Fixed commit is correct → a3 should NOT report that bug (else FP)

    Returns a dict describing the misclassification, or None if correct.
    """
    test_file = bug_info.get("test_file", "")

    # FALSE NEGATIVE: buggy code scans clean
    if buggy_result["verdict"] == "SAFE" and fixed_result["verdict"] == "SAFE":
        return {
            "type": "false_negative",
            "project": project,
            "bug_id": bug_id,
            "description": (
                f"a3 reported SAFE on BOTH buggy and fixed versions of "
                f"{project} bug #{bug_id}. The buggy version has a known bug "
                f"(test: {test_file}) that a3 failed to detect."
            ),
            "buggy_output": buggy_result["stdout"][:2000],
            "fixed_output": fixed_result["stdout"][:2000],
            "buggy_bugs": buggy_result["bugs_found"],
            "fixed_bugs": fixed_result["bugs_found"],
        }

    # FALSE POSITIVE: fixed code still flagged
    if fixed_result["verdict"] == "BUG" and fixed_result["bugs_found"]:
        buggy_bug_set = set(buggy_result.get("bugs_found", []))
        fixed_bug_set = set(fixed_result.get("bugs_found", []))

        # Bugs only in fixed version (not in buggy) → FP
        fixed_only_bugs = [b for b in fixed_result["bugs_found"] if b not in buggy_bug_set]
        if fixed_only_bugs:
            return {
                "type": "false_positive",
                "project": project,
                "bug_id": bug_id,
                "description": (
                    f"a3 reported bugs on the FIXED version of {project} bug #{bug_id} "
                    f"that weren't in the buggy version: {fixed_only_bugs[:5]}"
                ),
                "buggy_output": buggy_result["stdout"][:2000],
                "fixed_output": fixed_result["stdout"][:2000],
                "buggy_bugs": buggy_result["bugs_found"],
                "fixed_bugs": fixed_result["bugs_found"],
                "false_positive_bugs": fixed_only_bugs,
            }

        # Same bugs in both versions → a3 didn't recognize the fix
        if fixed_bug_set == buggy_bug_set and len(fixed_bug_set) > 0:
            return {
                "type": "same_findings",
                "project": project,
                "bug_id": bug_id,
                "description": (
                    f"a3 reported the EXACT SAME bugs on both buggy and fixed "
                    f"versions of {project} bug #{bug_id}. It failed to recognize "
                    f"the fix — false positives on fixed code."
                ),
                "buggy_output": buggy_result["stdout"][:2000],
                "fixed_output": fixed_result["stdout"][:2000],
                "buggy_bugs": buggy_result["bugs_found"],
                "fixed_bugs": fixed_result["bugs_found"],
            }

    return None


def classify_simple(pre_verdict: str, post_verdict: str) -> str:
    """Simple pre/post classification for reporting."""
    if pre_verdict == "BUG" and post_verdict == "SAFE":
        return "DETECTED"
    if pre_verdict == "BUG" and post_verdict == "BUG":
        return "PARTIAL"
    if pre_verdict == "SAFE" and post_verdict == "SAFE":
        return "MISSED"
    if pre_verdict == "SAFE" and post_verdict == "BUG":
        return "INVERTED"
    return "INCONCLUSIVE"


def infer_bug_type(message: str) -> str:
    """Infer a3-python bug type from commit message or patch context."""
    msg_lower = message.lower()
    for keyword, bug_type in BUG_KEYWORD_MAP.items():
        try:
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, msg_lower):
                return bug_type
        except re.error:
            if keyword in msg_lower:
                return bug_type
    return "unknown"


# ── ad-hoc git repo scanning (fallback for non-BugsInPy repos) ────────────────
def discover_repos(specific_repo: str = "") -> list[Path]:
    """Find local repos to scan, optionally clone new ones."""
    repos = []
    if specific_repo:
        p = Path(specific_repo)
        if p.exists():
            repos.append(p.resolve())
        elif specific_repo.startswith("http"):
            name = specific_repo.rstrip("/").split("/")[-1].replace(".git", "")
            dest = TEST_REPOS / name
            if not dest.exists():
                log(f"Cloning {specific_repo} → {dest}")
                TEST_REPOS.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["git", "clone", "--depth", "200", specific_repo, str(dest)],
                    capture_output=True, timeout=120,
                )
            if dest.exists():
                repos.append(dest)
    elif TEST_REPOS.exists():
        for child in sorted(TEST_REPOS.iterdir()):
            if child.is_dir() and (child / ".git").exists():
                repos.append(child)
    return repos


def find_bugfix_commits(repo: Path, max_commits: int = 50) -> list[dict]:
    """Search git history for bug-fix commits (ad-hoc repo mode)."""
    grep_terms = [
        "fix", "bug", "crash", "error", "exception", "overflow", "leak",
        "race", "null", "security", "vulnerability", "CVE",
        "IndexError", "KeyError", "TypeError", "ValueError",
    ]
    grep_args = []
    for term in grep_terms:
        grep_args.extend(["--grep", term])

    try:
        result = subprocess.run(
            ["git", "--no-pager", "log", "--oneline", "--all", "-i",
             f"--max-count={max_commits * 2}"] + grep_args,
            cwd=str(repo), capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return []

    commits = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.strip().split(" ", 1)
        sha, msg = parts[0], (parts[1] if len(parts) > 1 else "")

        try:
            diff_result = subprocess.run(
                ["git", "--no-pager", "diff", "--name-only", f"{sha}~1", sha, "--", "*.py"],
                cwd=str(repo), capture_output=True, text=True, timeout=10,
            )
            py_files = [f for f in diff_result.stdout.strip().splitlines() if f.endswith(".py")]
            if not py_files:
                continue
        except Exception:
            continue

        commits.append({
            "sha": sha, "message": msg, "py_files": py_files,
            "bug_type": infer_bug_type(msg),
        })
        if len(commits) >= max_commits:
            break
    return commits


def extract_file_at_commit(repo: Path, sha: str, filepath: str) -> Optional[str]:
    """Extract file content at a specific commit."""
    try:
        result = subprocess.run(
            ["git", "--no-pager", "show", f"{sha}:{filepath}"],
            cwd=str(repo), capture_output=True, text=True, timeout=10,
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: SCAN — BugsInPy-driven evaluation
# ══════════════════════════════════════════════════════════════════════════════
def phase_scan_bugsinpy(projects: list[str], max_bugs: int = 50) -> list[dict]:
    """Scan BugsInPy bugs: checkout buggy/fixed, scan with a3, classify."""
    all_results = []

    for project in projects:
        bug_ids = list_bugs(project)
        if not bug_ids:
            log(f"  No bugs found for {project}, skipping.")
            continue

        log(f"Scanning {project} ({len(bug_ids)} bugs)...")

        for bug_id in bug_ids[:max_bugs]:
            bug_info = get_bug_info(project, bug_id)
            patch_files = get_patch_files(project, bug_id)
            patch_context = get_patch_context(project, bug_id)
            bug_type_inferred = infer_bug_type(
                patch_context + " " + bug_info.get("test_file", ""))

            log(f"  {project} bug #{bug_id} (test: {bug_info.get('test_file', '?')[:40]})")

            buggy_dir = None
            fixed_dir = None
            try:
                buggy_dir = checkout_bug(project, bug_id, buggy=True)
                py_files_buggy = find_python_files(
                    buggy_dir, max_files=10, priority_files=patch_files)

                if not py_files_buggy:
                    log(f"    No Python files found, skipping.")
                    continue

                buggy_agg = scan_files_aggregate(py_files_buggy)

                fixed_dir = checkout_bug(project, bug_id, buggy=False)
                py_files_fixed = find_python_files(
                    fixed_dir, max_files=10, priority_files=patch_files)
                fixed_agg = scan_files_aggregate(py_files_fixed)

                classification = classify_simple(buggy_agg["verdict"], fixed_agg["verdict"])
                misclass = classify_bugsinpy_result(
                    project, bug_id, buggy_agg, fixed_agg, bug_info)

                entry = {
                    "source": "bugsinpy",
                    "project": project,
                    "bug_id": bug_id,
                    "test_file": bug_info.get("test_file", ""),
                    "patch_files": patch_files,
                    "bug_type_inferred": bug_type_inferred,
                    "buggy_verdict": buggy_agg["verdict"],
                    "fixed_verdict": fixed_agg["verdict"],
                    "buggy_bugs": buggy_agg["bugs_found"][:20],
                    "fixed_bugs": fixed_agg["bugs_found"][:20],
                    "buggy_output": buggy_agg["stdout"][:500],
                    "fixed_output": fixed_agg["stdout"][:500],
                    "classification": classification,
                    "misclass_type": misclass["type"] if misclass else None,
                    "misclass_description": misclass["description"] if misclass else None,
                    "should_detect": True,
                }
                all_results.append(entry)

                symbol = "✓" if misclass is None else "✗"
                log(f"    {symbol} {classification} "
                    f"(buggy={buggy_agg['verdict']}, fixed={fixed_agg['verdict']})"
                    + (f" [{misclass['type']}]" if misclass else ""))

            except Exception as e:
                log(f"    ERROR: {e}", "WARN")
                all_results.append({
                    "source": "bugsinpy",
                    "project": project,
                    "bug_id": bug_id,
                    "classification": "ERROR",
                    "error": str(e),
                    "should_detect": True,
                    "bug_type_inferred": bug_type_inferred,
                })
            finally:
                if buggy_dir:
                    cleanup_checkout(buggy_dir)
                if fixed_dir:
                    cleanup_checkout(fixed_dir)

    return all_results


def phase_scan_adhoc(repos: list[Path], max_commits: int = 50) -> list[dict]:
    """Scan ad-hoc repos by git history (fallback for non-BugsInPy repos)."""
    all_results = []
    for repo in repos:
        repo_name = repo.name
        log(f"Scanning {repo_name} (ad-hoc)...")
        try:
            subprocess.run(
                ["git", "fetch", "--deepen", "500"],
                cwd=str(repo), capture_output=True, timeout=60,
            )
        except Exception:
            pass

        commits = find_bugfix_commits(repo, max_commits=max_commits)
        log(f"  Found {len(commits)} bugfix commits in {repo_name}")

        for commit in commits:
            for py_file in commit["py_files"][:3]:
                pre_src = extract_file_at_commit(repo, f"{commit['sha']}~1", py_file)
                post_src = extract_file_at_commit(repo, commit["sha"], py_file)
                if not pre_src or not post_src:
                    continue

                # Write to temp files and scan
                import tempfile
                pre_result = _scan_source(pre_src)
                post_result = _scan_source(post_src)

                classification = classify_simple(pre_result["verdict"], post_result["verdict"])
                entry = {
                    "source": "git_history",
                    "project": repo_name,
                    "commit": commit["sha"],
                    "message": commit["message"],
                    "file": py_file,
                    "bug_type_inferred": commit["bug_type"],
                    "buggy_verdict": pre_result["verdict"],
                    "fixed_verdict": post_result["verdict"],
                    "buggy_bugs": pre_result["bugs_found"][:10],
                    "fixed_bugs": post_result["bugs_found"][:10],
                    "buggy_output": pre_result["stdout"][:300],
                    "fixed_output": post_result["stdout"][:300],
                    "classification": classification,
                    "should_detect": commit["bug_type"] != "unknown",
                }
                all_results.append(entry)

                log(f"  {commit['sha'][:7]} {py_file}: {classification} "
                    f"(pre={pre_result['verdict']}, post={post_result['verdict']})")

    return all_results


def _scan_source(source: str) -> dict:
    """Scan Python source string with a3 via temp file."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        tmp = Path(f.name)
    try:
        return scan_file_with_a3(tmp)
    finally:
        tmp.unlink(missing_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2: DIAGNOSE — analyze gaps, identify pathological patterns
# ══════════════════════════════════════════════════════════════════════════════
def phase_diagnose(results: list[dict]) -> dict:
    """Analyze scan results to find pathological gaps in a3-python."""
    total = len(results)
    by_class = defaultdict(list)
    detector_gaps = defaultdict(list)

    for r in results:
        by_class[r.get("classification", "ERROR")].append(r)

    detectable = [r for r in results if r.get("should_detect")]
    detected = [r for r in detectable if r["classification"] == "DETECTED"]
    partial = [r for r in detectable if r["classification"] == "PARTIAL"]
    missed = [r for r in detectable if r["classification"] == "MISSED"]
    inverted = [r for r in detectable if r["classification"] == "INVERTED"]
    false_negatives = [r for r in results if r.get("misclass_type") == "false_negative"]
    false_positives = [r for r in results if r.get("misclass_type") in ("false_positive", "same_findings")]

    detection_rate = len(detected) / max(len(detectable), 1)

    # Group missed/FN by inferred bug type → detector gaps
    for r in missed + false_negatives:
        bug_type = r.get("bug_type_inferred", "unknown")
        detector_file = DETECTOR_FILE_MAP.get(bug_type, "unknown")
        detector_gaps[detector_file].append(r)

    diagnosis = {
        "total_analyzed": total,
        "detectable": len(detectable),
        "detected": len(detected),
        "partial": len(partial),
        "missed": len(missed),
        "inverted": len(inverted),
        "false_negatives": len(false_negatives),
        "false_positives": len(false_positives),
        "inconclusive": len(by_class.get("INCONCLUSIVE", [])),
        "errors": len(by_class.get("ERROR", [])),
        "detection_rate": detection_rate,
        "detector_gaps": {
            det: [{"project": r.get("project", "?"),
                   "bug_id": r.get("bug_id", r.get("commit", "?")),
                   "classification": r["classification"],
                   "bug_type": r.get("bug_type_inferred", "?"),
                   "description": r.get("misclass_description", ""),
                   "buggy_output": r.get("buggy_output", "")[:300]}
                  for r in entries]
            for det, entries in detector_gaps.items()
        },
        "pathological_patterns": _identify_pathological_patterns(missed + false_negatives),
        "false_positive_entries": [
            {"project": r.get("project"), "bug_id": r.get("bug_id"),
             "description": r.get("misclass_description", "")}
            for r in false_positives[:20]
        ],
    }

    log(f"Diagnosis: {len(detected)} DETECTED, {len(partial)} PARTIAL, "
        f"{len(missed)} MISSED, {len(inverted)} INVERTED")
    log(f"  FN: {len(false_negatives)}, FP: {len(false_positives)}, "
        f"Errors: {len(by_class.get('ERROR', []))}")
    log(f"  Detection rate: {detection_rate:.1%}")

    return diagnosis


def _identify_pathological_patterns(missed_entries: list[dict]) -> list[dict]:
    """Identify recurring weakness patterns."""
    patterns = []
    type_counts = defaultdict(int)

    for r in missed_entries:
        type_counts[r.get("bug_type_inferred", "unknown")] += 1

    for bug_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        examples = [r for r in missed_entries if r.get("bug_type_inferred") == bug_type]
        detector = DETECTOR_FILE_MAP.get(bug_type, "unknown")
        patterns.append({
            "bug_type": bug_type,
            "count": count,
            "detector_file": detector,
            "severity": "HIGH" if count >= 3 else "MEDIUM" if count >= 2 else "LOW",
            "examples": [
                {"project": e.get("project", "?"),
                 "bug_id": e.get("bug_id", e.get("commit", "?")[:7]),
                 "description": (e.get("misclass_description") or e.get("message", ""))[:80]}
                for e in examples[:5]
            ],
        })

    return patterns


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3: IMPROVE — copilot-driven targeted fixes with verify loop
# ══════════════════════════════════════════════════════════════════════════════
def phase_improve(diagnosis: dict, results: list[dict], iteration: int,
                  dry_run: bool = False, model: str = "claude-sonnet-4") -> bool:
    """Generate and apply improvements, then verify with re-scan."""
    gaps = diagnosis.get("detector_gaps", {})
    patterns = diagnosis.get("pathological_patterns", [])
    fp_entries = diagnosis.get("false_positive_entries", [])

    if not gaps and not patterns and not fp_entries:
        log("No gaps to fix — all bugs detected!")
        return False

    # Pick the worst misclassification to fix first (BugsInPy-style)
    worst = _pick_worst_misclass(results)
    if worst:
        prompt = _build_targeted_fix_prompt(worst, diagnosis, iteration)
    else:
        prompt = _build_improvement_prompt(diagnosis, iteration)

    prompt_file = RESULTS_DIR / f"improvement_prompt_iter{iteration}.md"
    prompt_file.write_text(prompt)
    log(f"Improvement prompt saved to {prompt_file}")

    if dry_run:
        log("DRY RUN — skipping copilot execution")
        return False

    # Try fix with verification loop (like iterative_bugsinpy_improve.py)
    for retry in range(MAX_FIX_RETRIES):
        log(f"Fix attempt {retry + 1}/{MAX_FIX_RETRIES}...")
        success = _run_copilot(prompt, model=model)

        if not success:
            log(f"Copilot did not apply fix on attempt {retry + 1}", "WARN")
            continue

        # Verify: re-scan the specific bug that failed
        if worst and worst.get("source") == "bugsinpy":
            verified = _verify_bugsinpy_fix(worst)
            if verified:
                log("Fix verified! Re-scan confirms improvement.")
                return True
            else:
                log("Fix not verified — re-scan still shows same issue.")
        else:
            log("Improvement applied (no targeted verification available)")
            return True

    log(f"Max retries ({MAX_FIX_RETRIES}) exhausted")
    return True  # still proceed to next iteration


def _pick_worst_misclass(results: list[dict]) -> dict | None:
    """Pick the first false negative or false positive to fix."""
    for r in results:
        if r.get("misclass_type") == "false_negative":
            return r
    for r in results:
        if r.get("misclass_type") in ("false_positive", "same_findings"):
            return r
    # Fallback: first MISSED
    for r in results:
        if r.get("classification") == "MISSED" and r.get("should_detect"):
            return r
    return None


def _verify_bugsinpy_fix(entry: dict) -> bool:
    """Re-scan a specific BugsInPy bug to verify the fix worked."""
    project = entry.get("project")
    bug_id = entry.get("bug_id")
    if not project or not bug_id:
        return False

    patch_files = get_patch_files(project, bug_id)
    bug_info = get_bug_info(project, bug_id)
    buggy_dir = None
    fixed_dir = None

    try:
        if entry.get("misclass_type") == "false_negative":
            buggy_dir = checkout_bug(project, bug_id, buggy=True)
            py_files = find_python_files(buggy_dir, max_files=10, priority_files=patch_files)
            result = scan_files_aggregate(py_files)
            return result["verdict"] == "BUG"
        elif entry.get("misclass_type") in ("false_positive", "same_findings"):
            fixed_dir = checkout_bug(project, bug_id, buggy=False)
            py_files = find_python_files(fixed_dir, max_files=10, priority_files=patch_files)
            result = scan_files_aggregate(py_files)
            return result["verdict"] != "BUG" or len(result["bugs_found"]) == 0
        return False
    except Exception as e:
        log(f"  Verification error: {e}", "WARN")
        return False
    finally:
        if buggy_dir:
            cleanup_checkout(buggy_dir)
        if fixed_dir:
            cleanup_checkout(fixed_dir)


def _build_targeted_fix_prompt(entry: dict, diagnosis: dict, iteration: int) -> str:
    """Build a targeted prompt for a specific FP/FN (BugsInPy-style)."""
    project = entry.get("project", "?")
    bug_id = entry.get("bug_id", "?")
    misclass_type = entry.get("misclass_type", "false_negative")
    patch_context = ""
    if entry.get("source") == "bugsinpy":
        patch_context = get_patch_context(project, bug_id)

    if misclass_type == "false_negative":
        return textwrap.dedent(f"""\
        I am improving a3-python, a Python static analysis tool in this workspace (a3_python/ directory).

        FALSE NEGATIVE: a3-python missed a known bug from the BugsInPy benchmark.

        Project     : {project}
        Bug ID      : {bug_id}
        Bug category: {entry.get('bug_type_inferred', 'unknown')}
        Expected a3 bug type: {entry.get('bug_type_inferred', 'unknown')}
        Test file   : {entry.get('test_file', '?')}

        a3 output on buggy code (excerpt):
        {entry.get('buggy_output', 'N/A')[:1500]}

        Bug patch (what the fix changed):
        {patch_context[:2000]}

        The a3 analyzer failed to detect this bug. Please investigate the a3-python
        source code and improve the analysis to detect this class of bug.

        Detection rate this iteration: {diagnosis['detection_rate']:.1%}
        ({diagnosis['detected']}/{diagnosis['detectable']} detected,
         {diagnosis['missed']} missed, {diagnosis.get('false_negatives', 0)} FN)

        Common causes of false negatives:
        - Missing bug pattern in is_unsafe_* predicate
        - Analysis not reaching the buggy code path
        - Insufficient symbolic execution depth
        - Missing bytecode/AST pattern recognition
        - Overly strict preconditions in the detector

        Make targeted but potentially large changes. Do NOT break existing functionality.
        After changes, verify: python3 -m pytest tests/ -x -q 2>&1 | tail -20
        """)
    else:
        return textwrap.dedent(f"""\
        I am improving a3-python, a Python static analysis tool in this workspace (a3_python/ directory).

        FALSE POSITIVE: a3-python incorrectly reports bugs on fixed code.

        Project     : {project}
        Bug ID      : {bug_id}
        Bug category: {entry.get('bug_type_inferred', 'unknown')}
        Misclass    : {misclass_type}

        a3 output on FIXED code (excerpt):
        {entry.get('fixed_output', 'N/A')[:1500]}

        Bugs reported on fixed code: {entry.get('fixed_bugs', [])[:10]}

        Bug patch (what the fix changed):
        {patch_context[:2000]}

        The a3 analyzer incorrectly reports bugs on code that is actually correct.
        Please investigate and fix the analysis logic to avoid this false positive.

        Common causes:
        - Over-aggressive bug detection patterns
        - Missing guard/sanitizer recognition
        - Missing control flow analysis proving the path infeasible
        - Missing recognition of safe coding patterns

        Make targeted but potentially large changes. Do NOT break existing functionality.
        After changes, verify: python3 -m pytest tests/ -x -q 2>&1 | tail -20
        """)


def _build_improvement_prompt(diagnosis: dict, iteration: int) -> str:
    """Build a general improvement prompt from diagnosis."""
    patterns = diagnosis.get("pathological_patterns", [])
    gaps = diagnosis.get("detector_gaps", {})

    detector_sections = []
    for pattern in patterns:
        if pattern["severity"] == "LOW":
            continue
        det_file = pattern["detector_file"]
        bug_type = pattern["bug_type"]
        example_text = "\n".join(
            f"  - {e['project']} (bug {e['bug_id']}): {e['description']}"
            for e in pattern["examples"]
        )
        gap_entries = gaps.get(det_file, [])
        detail_text = ""
        for g in gap_entries[:3]:
            detail_text += f"\n  a3 output: {g.get('buggy_output', 'N/A')[:200]}"

        detector_sections.append(f"""
### Fix {det_file} — missed {pattern['count']} {bug_type} bug(s) [{pattern['severity']}]

**Missed examples:**
{example_text}
{detail_text}

**Required change:** Strengthen the `is_unsafe_*` predicate in `{det_file}`.
Consider: expanding pattern recognition, relaxing overly strict preconditions,
adding new symbolic state checks, improving taint propagation.
""")

    sections_text = "\n".join(detector_sections)

    return f"""You are running iteration {iteration} of the a3-python bugfix improvement pipeline.
Do the ENTIRE workflow yourself without asking me anything. Work until done.

## Current Detection Performance
- Detection rate: {diagnosis['detection_rate']:.1%}
- Detected: {diagnosis['detected']} / {diagnosis['detectable']} detectable bugs
- Partial: {diagnosis['partial']}
- Missed: {diagnosis['missed']} (failed to detect known bugs)
- False negatives: {diagnosis.get('false_negatives', 0)}
- False positives: {diagnosis.get('false_positives', 0)}
- Inverted: {diagnosis.get('inverted', 0)}

## Pathological Gaps
{sections_text}

## Instructions
1. Read each detector file listed above
2. Identify the `is_unsafe_*` predicate and detection logic
3. Make MINIMAL, SURGICAL changes to improve detection
4. Do NOT break existing detections
5. After changes: python3 -m pytest tests/ -x -q 2>&1 | tail -20

## Working directories
- Core detectors: a3_python/unsafe/*.py
- Security detectors: a3_python/unsafe/security/*.py
- Tests: tests/

Make the changes now. Work autonomously.
"""


def _run_copilot(prompt: str, model: str = "claude-sonnet-4") -> bool:
    """Run copilot CLI in non-interactive autopilot mode."""
    cmd = [
        "copilot",
        "-p", prompt,
        "--yolo",
        "--autopilot",
        "--no-ask-user",
        "--experimental",
        "--model", model,
    ]
    log(f"Launching: copilot --yolo --autopilot --model {model}")
    try:
        proc = subprocess.run(cmd, cwd=str(WORKSPACE), timeout=COPILOT_TIMEOUT)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        log(f"Copilot timed out after {COPILOT_TIMEOUT}s", "WARN")
        return False
    except FileNotFoundError:
        log("copilot CLI not found — skipping improvement phase", "ERROR")
        return False
    except Exception as e:
        log(f"Copilot error: {e}", "ERROR")
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  REPORTING — generate deliverables
# ══════════════════════════════════════════════════════════════════════════════
def save_results(results: list[dict], diagnosis: dict, iteration: int):
    """Save structured results and human-readable report."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    report_data = {
        "iteration": iteration,
        "timestamp": datetime.now().isoformat(),
        "diagnosis": diagnosis,
        "entries": results,
    }
    json_file = RESULTS_DIR / "bugfix_report.json"
    json_file.write_text(json.dumps(report_data, indent=2, default=str))
    log(f"JSON report: {json_file}")

    md = _generate_markdown_report(results, diagnosis, iteration)
    md_file = RESULTS_DIR / "bugfix_report.md"
    md_file.write_text(md)
    log(f"Markdown report: {md_file}")


def _generate_markdown_report(results: list[dict], diagnosis: dict, iteration: int) -> str:
    """Generate comprehensive markdown analysis report."""
    d = diagnosis
    patterns = d.get("pathological_patterns", [])

    pattern_rows = ""
    for p in patterns:
        examples_str = "; ".join(
            f"{e['project']}(#{e['bug_id']})" for e in p["examples"][:3])
        pattern_rows += (
            f"| {p['bug_type']} | {p['count']} | {p['severity']} | "
            f"`{p['detector_file']}` | {examples_str} |\n"
        )

    by_class = defaultdict(list)
    for r in results:
        by_class[r.get("classification", "ERROR")].append(r)

    class_details = ""
    for cls in ["DETECTED", "PARTIAL", "MISSED", "INVERTED", "INCONCLUSIVE", "ERROR"]:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        class_details += f"\n### {cls} ({len(entries)})\n\n"
        for e in entries[:15]:
            proj = e.get("project", "?")
            bug_id = e.get("bug_id", e.get("commit", "?"))
            class_details += (
                f"- **{proj}** bug #{bug_id} — "
                f"buggy={e.get('buggy_verdict', '?')} → "
                f"fixed={e.get('fixed_verdict', '?')}"
            )
            if e.get("misclass_type"):
                class_details += f" [{e['misclass_type']}]"
            class_details += "\n"
        if len(entries) > 15:
            class_details += f"- ... and {len(entries) - 15} more\n"

    fp_section = ""
    fp_entries = d.get("false_positive_entries", [])
    if fp_entries:
        fp_section = "\n## False Positives\n\n"
        for fp in fp_entries[:10]:
            fp_section += f"- **{fp['project']}** bug #{fp['bug_id']}: {fp['description'][:100]}\n"

    return f"""# a3-python Bugfix Evaluation Report — Iteration {iteration}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Source:** BugsInPy benchmark + ad-hoc repos

## Executive Summary

| Metric | Value |
|--------|-------|
| Total analyzed | {d['total_analyzed']} |
| Detectable | {d['detectable']} |
| **Detection rate** | **{d['detection_rate']:.1%}** |
| Detected (BUG→SAFE) | {d['detected']} |
| Partial (BUG→BUG) | {d['partial']} |
| Missed (SAFE→SAFE) | {d['missed']} |
| Inverted (SAFE→BUG) | {d.get('inverted', 0)} |
| False negatives | {d.get('false_negatives', 0)} |
| False positives | {d.get('false_positives', 0)} |
| Errors | {d.get('errors', 0)} |

## Pathological Patterns

| Bug Type | Count | Severity | Detector | Examples |
|----------|-------|----------|----------|----------|
{pattern_rows}

## Detailed Results
{class_details}
{fp_section}

## Root Cause Analysis

{_root_cause_section(patterns)}

## Recommendations

{_recommendations_section(patterns)}
"""


def _root_cause_section(patterns: list[dict]) -> str:
    sections = []
    for i, p in enumerate(patterns, 1):
        sections.append(
            f"### {i}. {p['bug_type']} detection gap ({p['detector_file']})\n"
            f"- **{p['count']}** bugs missed\n"
            f"- Severity: **{p['severity']}**\n"
            f"- Likely cause: `is_unsafe_*` predicate too conservative "
            f"or missing pattern recognition\n"
        )
    return "\n".join(sections) if sections else "No significant gaps identified."


def _recommendations_section(patterns: list[dict]) -> str:
    recs = []
    for i, p in enumerate(patterns, 1):
        recs.append(
            f"{i}. **Strengthen {p['bug_type']} detection** in `{p['detector_file']}`\n"
            f"   - Expand symbolic state matching\n"
            f"   - Add bytecode-level pattern recognition for missed shapes\n"
        )
    return "\n".join(recs) if recs else "All detectors performing well."


# ══════════════════════════════════════════════════════════════════════════════
#  STATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"iterations": [], "current_iteration": 0, "passed": [], "fixes_applied": 0}


def save_state(state: dict):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, default=str))


def should_stop(state: dict) -> bool:
    iters = state.get("iterations", [])
    if len(iters) < PLATEAU_PATIENCE + 1:
        return False
    recent_rates = [it["detection_rate"] for it in iters[-(PLATEAU_PATIENCE + 1):]]
    for i in range(1, len(recent_rates)):
        if recent_rates[i] - recent_rates[i - 1] >= PLATEAU_THRESHOLD:
            return False
    log(f"Plateau: last {PLATEAU_PATIENCE} iters improved < {PLATEAU_THRESHOLD:.0%}")
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE LOOP
# ══════════════════════════════════════════════════════════════════════════════
def run_pipeline(
    projects: list[str] | None = None,
    specific_repo: str = "",
    max_bugs: int = 50,
    max_commits: int = 50,
    max_iterations: int = DEFAULT_MAX_ITERS,
    scan_only: bool = False,
    dry_run: bool = False,
    resume: bool = False,
    model: str = "claude-sonnet-4",
):
    """Run the full scan → diagnose → improve pipeline."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    CHECKOUT_DIR.mkdir(parents=True, exist_ok=True)

    state = load_state() if resume else {
        "iterations": [], "current_iteration": 0,
        "passed": [], "fixes_applied": 0,
    }
    start_iter = state["current_iteration"] + 1 if resume else 1

    # Determine what to scan
    use_bugsinpy = not specific_repo
    if use_bugsinpy:
        ensure_bugsinpy_cloned()
        scan_projects = projects or PROJECTS
        log(f"Pipeline: BugsInPy mode, {len(scan_projects)} projects, "
            f"max {max_iterations} iterations")
    else:
        repos = discover_repos(specific_repo)
        if not repos:
            log("No repos found to scan", "ERROR")
            return 1
        log(f"Pipeline: ad-hoc mode, {len(repos)} repo(s), "
            f"max {max_iterations} iterations")

    for iteration in range(start_iter, max_iterations + 1):
        state["current_iteration"] = iteration

        # ── Phase 1: SCAN ──────────────────────────────────────────────
        log_phase("SCAN", iteration)
        if use_bugsinpy:
            results = phase_scan_bugsinpy(scan_projects, max_bugs=max_bugs)
        else:
            results = phase_scan_adhoc(repos, max_commits=max_commits)

        if not results:
            log("No results from scan", "WARN")
            state["iterations"].append({
                "iteration": iteration, "total": 0, "detection_rate": 0,
                "detected": 0, "partial": 0, "missed": 0, "detectable": 0,
                "false_negatives": 0, "false_positives": 0,
                "pathological_patterns": [],
            })
            save_state(state)
            if scan_only or iteration >= 2:
                break
            continue

        # ── Phase 2: DIAGNOSE ──────────────────────────────────────────
        log_phase("DIAGNOSE", iteration)
        diagnosis = phase_diagnose(results)
        save_results(results, diagnosis, iteration)

        state["iterations"].append({
            "iteration": iteration,
            "timestamp": datetime.now().isoformat(),
            "total": diagnosis["total_analyzed"],
            "detectable": diagnosis["detectable"],
            "detected": diagnosis["detected"],
            "partial": diagnosis["partial"],
            "missed": diagnosis["missed"],
            "false_negatives": diagnosis.get("false_negatives", 0),
            "false_positives": diagnosis.get("false_positives", 0),
            "detection_rate": diagnosis["detection_rate"],
            "pathological_patterns": [
                {"bug_type": p["bug_type"], "count": p["count"], "severity": p["severity"]}
                for p in diagnosis.get("pathological_patterns", [])
            ],
        })
        save_state(state)

        if scan_only:
            log("SCAN-ONLY mode — skipping improvement phase")
            break

        if (diagnosis["missed"] == 0 and diagnosis.get("false_negatives", 0) == 0
                and diagnosis.get("false_positives", 0) == 0):
            log("All bugs correctly classified — pipeline complete! 🎉")
            break

        if should_stop(state):
            log("Detection rate plateau — stopping pipeline")
            break

        # ── Phase 3: IMPROVE ───────────────────────────────────────────
        log_phase("IMPROVE", iteration)
        improved = phase_improve(
            diagnosis, results, iteration, dry_run=dry_run, model=model)

        if not improved:
            log("No improvements applied — stopping pipeline")
            break

        state["fixes_applied"] = state.get("fixes_applied", 0) + 1
        save_state(state)
        log(f"Iteration {iteration} complete — looping for re-scan\n")

    _print_summary(state)
    return 0


def _print_summary(state: dict):
    """Print pipeline execution summary."""
    iters = state.get("iterations", [])
    print(f"\n{'='*70}")
    print("  PIPELINE SUMMARY")
    print(f"{'='*70}")
    print(f"  Fixes applied: {state.get('fixes_applied', 0)}")
    print(f"\n{'Iter':<6} {'Total':<7} {'Detect':<8} {'Missed':<8} "
          f"{'FN':<5} {'FP':<5} {'Rate':<8} {'Patterns'}")
    print("-" * 70)
    for it in iters:
        patterns = ", ".join(
            f"{p['bug_type']}({p['count']})"
            for p in it.get("pathological_patterns", [])
        ) or "—"
        print(f"{it['iteration']:<6} {it.get('total', 0):<7} "
              f"{it.get('detected', 0):<8} {it.get('missed', 0):<8} "
              f"{it.get('false_negatives', 0):<5} {it.get('false_positives', 0):<5} "
              f"{it.get('detection_rate', 0):<8.1%} {patterns}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Bugfix-driven improvement pipeline for a3-python (BugsInPy + ad-hoc)")
    parser.add_argument("--project", type=str, default="",
                        help="Single BugsInPy project to scan (default: all 17)")
    parser.add_argument("--repo", type=str, default="",
                        help="Ad-hoc repo path or URL (bypasses BugsInPy)")
    parser.add_argument("--repo-url", type=str, default="",
                        help="GitHub URL to clone and scan (ad-hoc mode)")
    parser.add_argument("--max-bugs", type=int, default=50,
                        help="Max bugs per BugsInPy project (default: 50)")
    parser.add_argument("--max-commits", type=int, default=50,
                        help="Max commits for ad-hoc repo mode (default: 50)")
    parser.add_argument("--max-iterations", type=int, default=DEFAULT_MAX_ITERS,
                        help=f"Max pipeline iterations (default: {DEFAULT_MAX_ITERS})")
    parser.add_argument("--model", type=str, default="claude-sonnet-4",
                        help="Copilot model for improvement phase")
    parser.add_argument("--scan-only", action="store_true",
                        help="Run scan + diagnose only, no improvements")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate prompts but don't execute copilot")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last checkpoint")
    args = parser.parse_args()

    specific_repo = args.repo or args.repo_url or ""
    projects = [args.project] if args.project else None

    return run_pipeline(
        projects=projects,
        specific_repo=specific_repo,
        max_bugs=args.max_bugs,
        max_commits=args.max_commits,
        max_iterations=args.max_iterations,
        scan_only=args.scan_only,
        dry_run=args.dry_run,
        resume=args.resume,
        model=args.model,
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\nInterrupted by user. State saved.")
        sys.exit(130)
