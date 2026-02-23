#!/usr/bin/env python3
"""
Iterative self-improvement loop for a3-python using BugsInPy.

Outer loop: repeats indefinitely (Ctrl-C to stop)
  Inner loop: iterates over BugsInPy bugs, scans each with a3,
    compares to ground truth (buggy commit → should find bug,
    fixed commit → should be clean). On the first false positive
    or false negative, invokes copilot-cli to patch a3-python's
    implementation, then re-scans to verify the fix before
    moving on.

Prerequisites:
  - BugsInPy repo cloned (auto-cloned on first run)
  - a3 installed in dev mode (pip install -e .)
  - copilot CLI available via VS Code
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path


# ── Configuration ────────────────────────────────────────────────────────────

BUGSINPY_REPO = "https://github.com/soarsmu/BugsInPy.git"
BUGSINPY_DIR = Path(__file__).resolve().parent.parent / "BugsInPy"
A3_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = A3_ROOT / "bugsinpy_workspace"
STATE_FILE = A3_ROOT / "bugsinpy_iteration_state.json"
LOG_FILE = A3_ROOT / "bugsinpy_improvement.log"
COPILOT_CLI = (
    "copilot"
)

# BugsInPy projects to iterate over (all 17)
PROJECTS = [
    "PySnooper", "ansible", "black", "cookiecutter", "fastapi",
    "httpie", "keras", "luigi", "matplotlib", "pandas",
    "sanic", "scrapy", "spacy", "thefuck", "tornado",
    "tqdm", "youtube-dl",
]

# Maximum retries for copilot to fix a single issue
MAX_FIX_RETRIES = 3

# Timeout for a3 scan (seconds)
A3_SCAN_TIMEOUT = 120

# Timeout for copilot-cli call (seconds)
COPILOT_TIMEOUT = 3600


# ── Logging ──────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    """Print and append to log file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ── State management ────────────────────────────────────────────────────────

def load_state() -> dict:
    """Load iteration state (which bugs we've already passed)."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"passed": [], "iteration": 0, "fixes_applied": 0}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ── BugsInPy helpers ────────────────────────────────────────────────────────

def ensure_bugsinpy_cloned() -> None:
    """Clone BugsInPy if not already present."""
    if BUGSINPY_DIR.exists():
        log(f"BugsInPy already cloned at {BUGSINPY_DIR}")
        return
    log(f"Cloning BugsInPy to {BUGSINPY_DIR} ...")
    subprocess.run(
        ["git", "clone", "--depth=1", BUGSINPY_REPO, str(BUGSINPY_DIR)],
        check=True,
    )
    log("BugsInPy cloned successfully.")


def list_bugs(project: str) -> list[int]:
    """Return sorted list of bug IDs for a BugsInPy project."""
    bugs_dir = BUGSINPY_DIR / "projects" / project / "bugs"
    if not bugs_dir.exists():
        return []
    bug_ids = []
    for d in bugs_dir.iterdir():
        if d.is_dir() and d.name.isdigit():
            bug_ids.append(int(d.name))
    return sorted(bug_ids)


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


def checkout_bug(project: str, bug_id: int, buggy: bool = True) -> Path:
    """
    Checkout a BugsInPy bug (buggy or fixed version) into workspace.
    Returns the path to the checked-out source tree.

    Uses git to clone the project at the appropriate commit.
    """
    bug_info = get_bug_info(project, bug_id)
    project_info = get_project_info(project)

    github_url = project_info.get("github_url", "")
    if not github_url:
        raise ValueError(f"No github_url for project {project}")

    commit_id = bug_info.get("buggy_commit_id" if buggy else "fixed_commit_id", "")
    if not commit_id:
        raise ValueError(f"No {'buggy' if buggy else 'fixed'}_commit_id for {project} bug {bug_id}")

    version_label = "buggy" if buggy else "fixed"
    checkout_dir = WORKSPACE_DIR / f"{project}_bug{bug_id}_{version_label}"

    if checkout_dir.exists():
        shutil.rmtree(checkout_dir)

    checkout_dir.mkdir(parents=True, exist_ok=True)

    log(f"  Cloning {project} at {version_label} commit {commit_id[:8]}...")

    # Clone with depth to speed things up, then checkout the specific commit
    try:
        subprocess.run(
            ["git", "clone", "--depth=50", github_url, str(checkout_dir)],
            check=True,
            capture_output=True,
            timeout=120,
        )
        subprocess.run(
            ["git", "-C", str(checkout_dir), "fetch", "--depth=50", "origin", commit_id],
            capture_output=True,
            timeout=60,
        )
        subprocess.run(
            ["git", "-C", str(checkout_dir), "checkout", commit_id],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log(f"  WARNING: Could not checkout {project} bug {bug_id}: {e}")
        if checkout_dir.exists():
            shutil.rmtree(checkout_dir)
        raise

    return checkout_dir


def get_patch_files(project: str, bug_id: int) -> list[str]:
    """Extract changed source file paths from BugsInPy bug_patch.txt."""
    patch_file = BUGSINPY_DIR / "projects" / project / "bugs" / str(bug_id) / "bug_patch.txt"
    if not patch_file.exists():
        return []
    changed = []
    for line in patch_file.read_text().splitlines():
        # Parse "diff --git a/path b/path" or "+++ b/path" lines
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
    # Deduplicate while preserving order
    seen = set()
    result = []
    for p in changed:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def find_python_files(directory: Path, max_files: int = 20,
                      priority_files: list[str] | None = None) -> list[Path]:
    """Find Python source files in a directory (excluding tests, setup, etc.).

    If priority_files is given (relative paths), those files are placed first
    in the result list and count toward max_files.
    """
    skip_dirs = {
        "__pycache__", ".git", "venv", ".venv", "node_modules",
        ".egg-info", "dist", "build", ".tox", ".mypy_cache",
        "tests", "test", "testing", "docs", "doc", "examples",
        "benchmarks", "scripts",
    }

    # Resolve priority files first
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
        # Prune skip directories
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("test_") and f != "setup.py" and f != "conftest.py":
                candidate = Path(root) / f
                if candidate.resolve() not in priority_set:
                    py_files.append(candidate)
                    if len(py_files) >= max_files:
                        return py_files
    return py_files


# ── a3 scanning ──────────────────────────────────────────────────────────────

def scan_file_with_a3(filepath: Path) -> dict:
    """
    Scan a single Python file with a3 and return structured results.

    Returns dict with:
      - exit_code: 0=SAFE, 1=BUG, 2=UNKNOWN, 3=ERROR
      - stdout: raw output
      - bugs_found: list of bug descriptions extracted from output
      - verdict: "SAFE" | "BUG" | "UNKNOWN" | "ERROR"
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "a3_python", str(filepath)],
            capture_output=True,
            text=True,
            timeout=A3_SCAN_TIMEOUT,
            cwd=str(A3_ROOT),
        )
        exit_code = result.returncode
        stdout = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return {
            "exit_code": 3,
            "stdout": "TIMEOUT",
            "bugs_found": [],
            "verdict": "ERROR",
        }
    except Exception as e:
        return {
            "exit_code": 3,
            "stdout": str(e),
            "bugs_found": [],
            "verdict": "ERROR",
        }

    # Extract bug descriptions from output
    bugs_found = []
    for line in stdout.splitlines():
        # Look for bug type indicators in output
        if any(kw in line.upper() for kw in ["BUG:", "VULNERABILITY:", "FINDING:", "⚠"]):
            bugs_found.append(line.strip())

    verdict_map = {0: "SAFE", 1: "BUG", 2: "UNKNOWN"}
    verdict = verdict_map.get(exit_code, "ERROR")

    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "bugs_found": bugs_found,
        "verdict": verdict,
    }


def scan_directory_with_a3(directory: Path) -> dict:
    """
    Scan a project directory with a3 and return structured results.

    Uses --output-sarif for machine-readable output.
    """
    sarif_path = directory / "a3_results.sarif"
    json_path = directory / "a3_results.json"

    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "a3_python",
                str(directory),
                "--output-sarif", str(sarif_path),
                "--save-results", str(json_path),
                "--min-confidence", "0.5",
            ],
            capture_output=True,
            text=True,
            timeout=A3_SCAN_TIMEOUT,
            cwd=str(A3_ROOT),
        )
        exit_code = result.returncode
        stdout = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return {
            "exit_code": 3,
            "stdout": "TIMEOUT",
            "bugs_found": [],
            "verdict": "ERROR",
            "sarif": None,
            "json_results": None,
        }
    except Exception as e:
        return {
            "exit_code": 3,
            "stdout": str(e),
            "bugs_found": [],
            "verdict": "ERROR",
            "sarif": None,
            "json_results": None,
        }

    # Parse SARIF if available
    sarif_data = None
    if sarif_path.exists():
        try:
            sarif_data = json.loads(sarif_path.read_text())
        except Exception:
            pass

    # Parse JSON results if available
    json_results = None
    if json_path.exists():
        try:
            json_results = json.loads(json_path.read_text())
        except Exception:
            pass

    bugs_found = []
    if sarif_data:
        for run in sarif_data.get("runs", []):
            for r in run.get("results", []):
                bug_desc = f"{r.get('ruleId', '?')}: {r.get('message', {}).get('text', '?')}"
                bugs_found.append(bug_desc)
    elif json_results:
        for fn, bt in json_results.get("prod_bugs", []):
            bugs_found.append(f"{bt} in {fn}")

    verdict_map = {0: "SAFE", 1: "BUG", 2: "UNKNOWN"}
    verdict = verdict_map.get(exit_code, "ERROR")

    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "bugs_found": bugs_found,
        "verdict": verdict,
        "sarif": sarif_data,
        "json_results": json_results,
    }


# ── FP/FN classification ────────────────────────────────────────────────────

def classify_result(
    project: str,
    bug_id: int,
    buggy_result: dict,
    fixed_result: dict,
    bug_info: dict,
) -> dict | None:
    """
    Compare scan results for buggy vs fixed commits to detect FP/FN.

    Ground truth from BugsInPy:
      - Buggy commit has a real bug → a3 should report BUG (else FN)
      - Fixed commit has the bug fixed → a3 should NOT report a bug
        for that same location (else FP)

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
        # Check if the bugs reported on fixed code are also in the buggy code
        # (i.e., are they real bugs or FPs from fixed code?)
        fixed_only_bugs = []
        buggy_bug_set = set(buggy_result.get("bugs_found", []))
        for bug in fixed_result["bugs_found"]:
            if bug not in buggy_bug_set:
                fixed_only_bugs.append(bug)

        # If all bugs in fixed were also in buggy, that's a true positive
        # (the fix may not have addressed those specific bugs).
        # But if there are fixed-only bugs, those are clearly FPs.
        if fixed_only_bugs:
            return {
                "type": "false_positive",
                "project": project,
                "bug_id": bug_id,
                "description": (
                    f"a3 reported bugs on the FIXED version of {project} bug #{bug_id} "
                    f"that weren't in the buggy version. These are false positives: "
                    f"{fixed_only_bugs[:5]}"
                ),
                "buggy_output": buggy_result["stdout"][:2000],
                "fixed_output": fixed_result["stdout"][:2000],
                "buggy_bugs": buggy_result["bugs_found"],
                "fixed_bugs": fixed_result["bugs_found"],
                "false_positive_bugs": fixed_only_bugs,
            }

        # Also: if fixed version reports bugs but buggy version does too,
        # the bugs might be pre-existing issues (not related to the BugsInPy bug).
        # We still flag if the fixed version reports more than the buggy version.
        if len(fixed_result["bugs_found"]) > len(buggy_result["bugs_found"]):
            extra = len(fixed_result["bugs_found"]) - len(buggy_result["bugs_found"])
            return {
                "type": "false_positive",
                "project": project,
                "bug_id": bug_id,
                "description": (
                    f"a3 found {extra} more bugs on the FIXED version than the "
                    f"BUGGY version of {project} bug #{bug_id}. The extra reports "
                    f"are likely false positives."
                ),
                "buggy_output": buggy_result["stdout"][:2000],
                "fixed_output": fixed_result["stdout"][:2000],
                "buggy_bugs": buggy_result["bugs_found"],
                "fixed_bugs": fixed_result["bugs_found"],
            }

    return None


# ── Copilot-driven fix ───────────────────────────────────────────────────────

def call_copilot(prompt: str) -> str:
    """
    Invoke copilot-cli with a prompt and return its output.
    """
    # Use a list (no shell=True) so subprocess handles the spaces in the
    # COPILOT_CLI path and in the prompt correctly — no manual quoting needed.
    cmd = [
        str(COPILOT_CLI),
        "-p", "'" + prompt.replace("'", " ") + "'",
        "--autopilot",
        "--allow-all-tools",
    ]

    log(f"  Calling copilot-cli (prompt length: {len(prompt)} chars)...")

    try:
        # result = subprocess.run(
        #     cmd,
        #     capture_output=True,
        #     text=True,
        #     timeout=COPILOT_TIMEOUT,
        #     cwd=str(A3_ROOT),
        # )
        os.system(" ".join(cmd) + f" > {A3_ROOT / 'copilot_output.txt'} 2>&1")
        output = (A3_ROOT / "copilot_output.txt").read_text()
        return output
        # output = result.stdout + result.stderr
        # log(f"  Copilot returned (exit={result.returncode}, output length: {len(output)} chars)")
        # return output
    except subprocess.TimeoutExpired:
        log("  Copilot timed out!")
        return "COPILOT_TIMEOUT"
    except Exception as e:
        log(f"  Copilot error: {e}")
        return f"COPILOT_ERROR: {e}"


def attempt_fix(misclass: dict) -> bool:
    """
    Use copilot-cli to fix a false positive or false negative in a3-python.

    Returns True if the fix was applied (copilot made changes).
    """
    fp_or_fn = misclass["type"]
    project = misclass["project"]
    bug_id = misclass["bug_id"]

    if fp_or_fn == "false_positive":
        prompt = textwrap.dedent(f"""\
            I'm working on a3-python, a Python static analysis tool in this workspace.
            
            We have a FALSE POSITIVE issue:
            {misclass['description']}
            
            The a3 analyzer incorrectly reports bugs on code that is actually correct
            (the fixed version of {project} BugsInPy bug #{bug_id}).
            
            False positive bugs reported on fixed code:
            {json.dumps(misclass.get('false_positive_bugs', misclass.get('fixed_bugs', []))[:10], indent=2)}
            
            Relevant a3 output on fixed code (excerpt):
            {misclass['fixed_output'][:1500]}
            
            Please investigate the a3-python source code (in the a3_python/ directory)
            and fix the analysis logic to avoid this false positive. Common causes:
            - Over-aggressive bug detection patterns
            - Missing guard/sanitizer recognition
            - Missing control flow analysis that would prove the path is infeasible
            - Missing recognition of safe coding patterns
            
            Make targeted, minimal changes. Do NOT break existing functionality.
        """)
    else:  # false_negative
        prompt = textwrap.dedent(f"""\
            I'm working on a3-python, a Python static analysis tool in this workspace.
            
            We have a FALSE NEGATIVE issue:
            {misclass['description']}
            
            The a3 analyzer failed to detect a known bug in {project}
            (BugsInPy bug #{bug_id}).
            
            The buggy code was reported as SAFE, but it has a known bug that
            is exposed by the test: {misclass.get('test_file', 'unknown')}
            
            Relevant a3 output on buggy code (excerpt):
            {misclass['buggy_output'][:1500]}
            
            Please investigate the a3-python source code (in the a3_python/ directory)
            and improve the analysis to detect this class of bug. Common causes:
            - Missing bug pattern detection
            - Analysis not reaching the buggy code path
            - Insufficient symbolic execution depth
            - Missing unsafe predicate check
            
            Make targeted, minimal changes. Do NOT break existing functionality.
        """)

    output = call_copilot(prompt)

    # Check if copilot made code changes
    if "Total code changes:" in output:
        match = re.search(r"Total code changes:\s+\+(\d+)\s+-(\d+)", output)
        if match:
            added, removed = int(match.group(1)), int(match.group(2))
            if added > 0 or removed > 0:
                log(f"  Copilot made changes: +{added} -{removed}")
                return True

    log("  Copilot did not make any code changes.")
    return False


# ── Cleanup ──────────────────────────────────────────────────────────────────

def cleanup_checkout(checkout_dir: Path) -> None:
    """Remove a checked-out project directory."""
    if checkout_dir.exists():
        shutil.rmtree(checkout_dir, ignore_errors=True)


# ── Main loops ───────────────────────────────────────────────────────────────

def inner_loop(state: dict) -> bool:
    """
    Inner loop: iterate over BugsInPy bugs.
    
    For each bug:
      1. Checkout buggy and fixed versions
      2. Scan both with a3
      3. On first FP/FN, invoke copilot to fix a3
      4. Re-scan to verify fix
      5. If verified, continue; else retry up to MAX_FIX_RETRIES

    Returns True if a fix was applied and verified (or max retries hit).
    Returns False if no issues found (all bugs passed).
    """
    passed = set(tuple(x) for x in state.get("passed", []))

    for project in PROJECTS:
        bug_ids = list_bugs(project)
        if not bug_ids:
            log(f"  No bugs found for project {project}, skipping.")
            continue

        for bug_id in bug_ids:
            bug_key = (project, bug_id)
            if bug_key in passed:
                continue

            bug_info = get_bug_info(project, bug_id)
            log(f"\n  === {project} bug #{bug_id} ===")
            log(f"  Test: {bug_info.get('test_file', '?')}")
            log(f"  Python: {bug_info.get('python_version', '?')}")

            buggy_dir = None
            fixed_dir = None
            try:
                # Checkout buggy version
                buggy_dir = checkout_bug(project, bug_id, buggy=True)
                # Prioritize files changed in the bug patch
                patch_files = get_patch_files(project, bug_id)
                # Scan buggy version — use individual files for smaller projects
                py_files = find_python_files(buggy_dir, max_files=10,
                                             priority_files=patch_files)
                if not py_files:
                    log(f"  No Python source files found in buggy checkout, skipping.")
                    passed.add(bug_key)
                    state["passed"] = [list(x) for x in passed]
                    save_state(state)
                    continue

                log(f"  Scanning buggy version ({len(py_files)} files)...")
                buggy_results = []
                for pf in py_files:
                    r = scan_file_with_a3(pf)
                    buggy_results.append(r)

                # Aggregate buggy results
                buggy_agg = {
                    "exit_code": max(r["exit_code"] for r in buggy_results),
                    "stdout": "\n---\n".join(r["stdout"] for r in buggy_results)[:4000],
                    "bugs_found": [b for r in buggy_results for b in r["bugs_found"]],
                    "verdict": "BUG" if any(r["verdict"] == "BUG" for r in buggy_results) else
                              "UNKNOWN" if any(r["verdict"] == "UNKNOWN" for r in buggy_results) else
                              "SAFE",
                }

                # Checkout fixed version
                fixed_dir = checkout_bug(project, bug_id, buggy=False)
                py_files_fixed = find_python_files(fixed_dir, max_files=10,
                                                   priority_files=patch_files)

                log(f"  Scanning fixed version ({len(py_files_fixed)} files)...")
                fixed_results = []
                for pf in py_files_fixed:
                    r = scan_file_with_a3(pf)
                    fixed_results.append(r)

                # Aggregate fixed results
                fixed_agg = {
                    "exit_code": max(r["exit_code"] for r in fixed_results) if fixed_results else 0,
                    "stdout": "\n---\n".join(r["stdout"] for r in fixed_results)[:4000],
                    "bugs_found": [b for r in fixed_results for b in r["bugs_found"]],
                    "verdict": "BUG" if any(r["verdict"] == "BUG" for r in fixed_results) else
                              "UNKNOWN" if any(r["verdict"] == "UNKNOWN" for r in fixed_results) else
                              "SAFE",
                }

                # Classify
                misclass = classify_result(project, bug_id, buggy_agg, fixed_agg, bug_info)

                if misclass is None:
                    log(f"  ✓ {project} bug #{bug_id}: correct (buggy={buggy_agg['verdict']}, fixed={fixed_agg['verdict']})")
                    passed.add(bug_key)
                    state["passed"] = [list(x) for x in passed]
                    save_state(state)
                    continue

                # Found a misclassification — try to fix it
                log(f"  ✗ {misclass['type'].upper()}: {misclass['description'][:200]}")

                for retry in range(MAX_FIX_RETRIES):
                    log(f"  Fix attempt {retry + 1}/{MAX_FIX_RETRIES}...")
                    fix_applied = attempt_fix(misclass)

                    if not fix_applied:
                        log(f"  Copilot did not apply a fix, retrying with more context...")
                        continue

                    # Re-scan to verify
                    log(f"  Re-scanning to verify fix...")

                    if misclass["type"] == "false_positive":
                        # Re-scan fixed version — should now be SAFE
                        new_results = []
                        for pf in py_files_fixed:
                            r = scan_file_with_a3(pf)
                            new_results.append(r)
                        new_agg = {
                            "exit_code": max(r["exit_code"] for r in new_results) if new_results else 0,
                            "bugs_found": [b for r in new_results for b in r["bugs_found"]],
                            "verdict": "BUG" if any(r["verdict"] == "BUG" for r in new_results) else "SAFE",
                        }
                        if new_agg["verdict"] != "BUG" or len(new_agg["bugs_found"]) <= len(buggy_agg["bugs_found"]):
                            log(f"  ✓ Fix verified! False positive resolved.")
                            state["fixes_applied"] = state.get("fixes_applied", 0) + 1
                            passed.add(bug_key)
                            state["passed"] = [list(x) for x in passed]
                            save_state(state)
                            return True  # exit inner loop, restart
                        else:
                            log(f"  ✗ Fix did not resolve the false positive.")
                    else:
                        # Re-scan buggy version — should now detect the bug
                        new_results = []
                        for pf in py_files:
                            r = scan_file_with_a3(pf)
                            new_results.append(r)
                        new_agg = {
                            "bugs_found": [b for r in new_results for b in r["bugs_found"]],
                            "verdict": "BUG" if any(r["verdict"] == "BUG" for r in new_results) else "SAFE",
                        }
                        if new_agg["verdict"] == "BUG":
                            log(f"  ✓ Fix verified! False negative resolved — bug now detected.")
                            state["fixes_applied"] = state.get("fixes_applied", 0) + 1
                            passed.add(bug_key)
                            state["passed"] = [list(x) for x in passed]
                            save_state(state)
                            return True  # exit inner loop, restart
                        else:
                            log(f"  ✗ Fix did not resolve the false negative.")

                # Max retries exhausted
                log(f"  Max retries exhausted for {project} bug #{bug_id}. Marking as passed and continuing.")
                passed.add(bug_key)
                state["passed"] = [list(x) for x in passed]
                save_state(state)
                return True  # exit inner loop even if not fixed

            except Exception as e:
                log(f"  ERROR processing {project} bug #{bug_id}: {e}")
                # Skip this bug
                passed.add(bug_key)
                state["passed"] = [list(x) for x in passed]
                save_state(state)
                continue
            finally:
                # Cleanup checkouts to save disk space
                if buggy_dir:
                    cleanup_checkout(buggy_dir)
                if fixed_dir:
                    cleanup_checkout(fixed_dir)

    log("All BugsInPy bugs have been processed!")
    return False  # nothing left to fix


def outer_loop() -> None:
    """
    Outer loop: repeatedly runs the inner loop.
    Each inner loop pass either:
      - Finds and fixes one FP/FN, then restarts
      - Finds no issues (all passed), and exits
    """
    log("=" * 70)
    log("A³ Iterative Self-Improvement via BugsInPy")
    log("=" * 70)

    ensure_bugsinpy_cloned()
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    state = load_state()
    log(f"Resuming from iteration {state.get('iteration', 0)}, "
        f"{len(state.get('passed', []))} bugs already passed, "
        f"{state.get('fixes_applied', 0)} fixes applied so far.")

    while True:
        state["iteration"] = state.get("iteration", 0) + 1
        save_state(state)

        log(f"\n{'=' * 70}")
        log(f"OUTER LOOP ITERATION {state['iteration']}")
        log(f"{'=' * 70}")

        had_fix = inner_loop(state)

        if not had_fix:
            log("\nAll BugsInPy bugs processed with no remaining FP/FN issues!")
            log(f"Total fixes applied: {state.get('fixes_applied', 0)}")
            log(f"Total iterations: {state['iteration']}")
            break

        log(f"\nFix applied in iteration {state['iteration']}. "
            f"Total fixes so far: {state.get('fixes_applied', 0)}. "
            f"Restarting inner loop...")

    log("\n" + "=" * 70)
    log("DONE — iterative improvement complete.")
    log("=" * 70)


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        outer_loop()
    except KeyboardInterrupt:
        log("\nInterrupted by user. State saved.")
        sys.exit(130)
