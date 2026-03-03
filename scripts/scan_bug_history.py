#!/usr/bin/env python3
"""
scan_bug_history.py  —  Git-history bug scanner for a3-python
================================================================

Automatically fetches the 20 largest (by stars) Python repositories on
GitHub, clones each one into a local work directory, then walks the git
commit history and runs a3-python on every commit where Python files
changed.  For each changed file, compare the a3 verdict *before* and
*after* the commit to detect four events:

  BUG_INTRODUCED  – file was SAFE before but is BUG after
  BUG_FIXED       – file was BUG before but is SAFE after
  PERSISTS        – both sides report BUG (bug survived the commit)
  CLEAN           – both sides are SAFE (no bug in either version)

Usage
-----
  # Scan the last 50 commits of each of the top 20 Python repos
  python scripts/scan_bug_history.py

  # Use an authenticated GitHub token to avoid rate-limiting
  python scripts/scan_bug_history.py --github-token ghp_xxxx

  # Scan only 10 repos instead of 20
  python scripts/scan_bug_history.py --num-repos 10

  # Override where repos are cloned
  python scripts/scan_bug_history.py --workdir /tmp/a3_repos

  # Limit commits scanned per repo
  python scripts/scan_bug_history.py --limit 30

  # Save combined JSON + Markdown report
  python scripts/scan_bug_history.py \\
      --out results/bug_history.json \\
      --report results/bug_history.md

  # Use the a3 CLI instead of the Python API
  python scripts/scan_bug_history.py --use-cli

  # Only show commits that introduced or fixed a bug
  python scripts/scan_bug_history.py --events-only

Prerequisites
-------------
  pip install a3-python          # or pip install -e . from repo root
  git (must be on PATH)

Output
------
  results/bug_history.json       – machine-readable combined timeline
  results/bug_history.md         – human-readable per-repo report
  stdout                         – live progress + summary table
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Locate a3-python ─────────────────────────────────────────────────────────
A3_ROOT = Path(__file__).resolve().parent.parent
if str(A3_ROOT) not in sys.path:
    sys.path.insert(0, str(A3_ROOT))

# Default work directory for cloned repos
DEFAULT_WORKDIR = Path(tempfile.gettempdir()) / "a3_top_python_repos"

# ─── ANSI colours ─────────────────────────────────────────────────────────────
_TTY = sys.stdout.isatty()
RED    = "\033[31m" if _TTY else ""
GREEN  = "\033[32m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN   = "\033[36m" if _TTY else ""
BOLD   = "\033[1m"  if _TTY else ""
RESET  = "\033[0m"  if _TTY else ""


# ═══════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FileScanResult:
    """a3 result for a single file at a single commit."""
    verdict: str            # SAFE | BUG | UNKNOWN | ERROR
    bug_types: List[str] = field(default_factory=list)
    findings: List[dict]   = field(default_factory=list)
    duration_sec: float    = 0.0
    error: Optional[str]   = None


@dataclass
class CommitFileEvent:
    """What happened to one file at one commit."""
    commit_sha: str
    commit_short: str
    commit_date: str
    commit_msg: str
    author: str
    filepath: str           # repo-relative path
    event: str              # BUG_INTRODUCED | BUG_FIXED | PERSISTS | CLEAN
    before: FileScanResult
    after:  FileScanResult
    new_bug_types:  List[str] = field(default_factory=list)   # appeared
    fixed_bug_types: List[str]= field(default_factory=list)   # disappeared


@dataclass
class BugLifetime:
    """The full lifespan of a specific bug type in a specific file."""
    filepath: str
    bug_type: str
    introduced_sha: str
    introduced_date: str
    introduced_msg: str
    fixed_sha: Optional[str]   = None
    fixed_date: Optional[str]  = None
    fixed_msg: Optional[str]   = None
    still_present: bool        = True
    commits_alive: int         = 0


@dataclass
class ScanReport:
    repo: str
    branch: str
    subdir: str
    scanned_commits: int
    scanned_files: int
    total_file_scans: int
    events: List[CommitFileEvent] = field(default_factory=list)
    lifetimes: List[BugLifetime]  = field(default_factory=list)
    generated_at: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# GitHub repo discovery
# ═══════════════════════════════════════════════════════════════════════════

def fetch_top_python_repos(n: int = 20, token: Optional[str] = None) -> List[dict]:
    """Return metadata for the top-n most-starred Python repos on GitHub.

    Each dict has keys: name, full_name, clone_url, stargazers_count, description.
    Uses the GitHub Search API (unauthenticated: 10 req/min; authenticated: 30 req/min).
    """
    per_page = min(n, 100)
    url = (
        "https://api.github.com/search/repositories"
        f"?q=language:python&sort=stars&order=desc&per_page={per_page}"
    )
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "a3-python-scan-bug-history")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"{RED}GitHub API error {exc.code}: {exc.reason}{RESET}", file=sys.stderr)
        if exc.code == 403:
            print("  Hint: pass --github-token to avoid rate-limiting.", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"{RED}Network error fetching GitHub repos: {exc.reason}{RESET}", file=sys.stderr)
        sys.exit(1)

    repos = []
    for item in data.get("items", [])[:n]:
        repos.append({
            "name":             item["name"],
            "full_name":        item["full_name"],
            "clone_url":        item["clone_url"],
            "default_branch":   item.get("default_branch", "main"),
            "stargazers_count": item["stargazers_count"],
            "description":      (item.get("description") or "")[:120],
        })
    return repos


def clone_or_update_repo(clone_url: str, dest: Path) -> bool:
    """Shallow-clone a repo into dest, or fetch the latest if it already exists.

    Returns True on success, False on failure.
    """
    if (dest / ".git").exists():
        print(f"  {CYAN}Updating{RESET} {dest.name} …")
        result = subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth=1100", "--quiet"],
            capture_output=True, text=True
        )
        return result.returncode == 0
    else:
        print(f"  {CYAN}Cloning{RESET} {clone_url} …")
        dest.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth=1100", "--quiet", clone_url, str(dest)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  {RED}Clone failed:{RESET} {result.stderr.strip()}", file=sys.stderr)
            return False
        return True


# ═══════════════════════════════════════════════════════════════════════════
# Git helpers
# ═══════════════════════════════════════════════════════════════════════════

def _git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo)] + list(args),
        capture_output=True, text=True, check=check
    )
    return result.stdout.strip()


def get_commits(repo: Path, branch: str, limit: int, subdir: str) -> List[dict]:
    """Return a list of commit metadata dicts, newest-first."""
    fmt = "%H|%h|%ai|%s|%an"
    args = ["log", f"--format={fmt}", f"-{limit}", branch]
    if subdir:
        args += ["--", subdir]
    raw = _git(repo, *args)
    commits = []
    for line in raw.splitlines():
        parts = line.split("|", 4)
        if len(parts) == 5:
            commits.append({
                "sha":   parts[0],
                "short": parts[1],
                "date":  parts[2],
                "msg":   parts[3][:72],
                "author": parts[4],
            })
    return commits


def get_changed_python_files(repo: Path, commit_sha: str, subdir: str) -> List[str]:
    """Return repo-relative paths of .py files changed in this commit."""
    raw = _git(repo, "diff-tree", "--no-commit-id", "-r", "--name-only", commit_sha)
    files = [f for f in raw.splitlines() if f.endswith(".py")]
    if subdir:
        files = [f for f in files if f.startswith(subdir)]
    return files


def get_file_at_commit(repo: Path, commit_sha: str, filepath: str) -> Optional[str]:
    """Return file contents at a specific commit, or None if not present."""
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit_sha}:{filepath}"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return result.stdout
    return None


def get_parent_sha(repo: Path, commit_sha: str) -> Optional[str]:
    """Return the first parent SHA, or None for root commits."""
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{commit_sha}^"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return None


# ═══════════════════════════════════════════════════════════════════════════
# a3-python scan helpers
# ═══════════════════════════════════════════════════════════════════════════

def _scan_with_api(content: str, filename: str, timeout_ms: int) -> FileScanResult:
    """Scan file content using the a3-python Python API."""
    try:
        from a3_python.analyzer import Analyzer  # type: ignore
    except ImportError:
        try:
            from pyfromscratch.analyzer import Analyzer  # type: ignore
        except ImportError:
            return FileScanResult(verdict="ERROR", error="a3-python not importable")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py",
        prefix=f"a3hist_{Path(filename).stem}_",
        delete=False
    ) as f:
        f.write(content)
        tmp = Path(f.name)

    t0 = time.perf_counter()
    try:
        analyzer = Analyzer(max_paths=300, max_depth=150, timeout_ms=timeout_ms)
        result   = analyzer.analyze_file(str(tmp))
        elapsed  = time.perf_counter() - t0

        verdict   = getattr(result, "verdict", "UNKNOWN")
        bug_types = []
        findings  = []

        # Try to collect per-finding details
        if hasattr(result, "findings") and result.findings:
            for f_obj in result.findings:
                bt = getattr(f_obj, "bug_type", None) or getattr(f_obj, "type", None)
                if bt:
                    bug_types.append(str(bt))
                findings.append({
                    "bug_type": str(bt) if bt else "UNKNOWN",
                    "line": getattr(f_obj, "line", 0),
                    "message": str(getattr(f_obj, "message", "")),
                    "confidence": float(getattr(f_obj, "confidence", 0.0)),
                })
        elif verdict == "BUG":
            bt = getattr(result, "bug_type", None)
            if bt:
                bug_types = [str(bt)]

        return FileScanResult(
            verdict=str(verdict),
            bug_types=list(dict.fromkeys(bug_types)),  # deduplicate, preserve order
            findings=findings,
            duration_sec=round(elapsed, 3),
        )
    except Exception as exc:
        return FileScanResult(verdict="ERROR", error=str(exc),
                              duration_sec=round(time.perf_counter() - t0, 3))
    finally:
        tmp.unlink(missing_ok=True)


def _scan_with_cli(content: str, filename: str, timeout_s: int) -> FileScanResult:
    """Scan file content using the a3 CLI (mirrors what CI does)."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py",
        prefix=f"a3hist_{Path(filename).stem}_",
        delete=False
    ) as f:
        f.write(content)
        tmp = Path(f.name)

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ["a3", "scan", str(tmp), "--output-format", "json"],
            capture_output=True, text=True, timeout=timeout_s
        )
        elapsed = time.perf_counter() - t0
        try:
            data     = json.loads(proc.stdout)
            verdict  = data.get("verdict", "UNKNOWN")
            findings = data.get("findings", [])
            bug_types = list(dict.fromkeys(
                f.get("bug_type", "UNKNOWN") for f in findings
            ))
            return FileScanResult(
                verdict=verdict,
                bug_types=bug_types,
                findings=findings,
                duration_sec=round(elapsed, 3),
            )
        except json.JSONDecodeError:
            # Fall back to exit-code convention: 0=SAFE 1=BUG
            verdict = "BUG" if proc.returncode == 1 else "SAFE"
            return FileScanResult(
                verdict=verdict, duration_sec=round(elapsed, 3)
            )
    except subprocess.TimeoutExpired:
        return FileScanResult(
            verdict="ERROR", error="timeout",
            duration_sec=round(time.perf_counter() - t0, 3)
        )
    except Exception as exc:
        return FileScanResult(verdict="ERROR", error=str(exc),
                              duration_sec=round(time.perf_counter() - t0, 3))
    finally:
        tmp.unlink(missing_ok=True)


def scan_content(
    content: str,
    filename: str,
    use_cli: bool,
    timeout_ms: int,
) -> FileScanResult:
    if use_cli:
        return _scan_with_cli(content, filename, timeout_ms // 1000 or 30)
    return _scan_with_api(content, filename, timeout_ms)


# ═══════════════════════════════════════════════════════════════════════════
# Core scan loop
# ═══════════════════════════════════════════════════════════════════════════

def scan_history(
    repo: Path,
    branch: str,
    limit: int,
    subdir: str,
    use_cli: bool,
    timeout_ms: int,
    events_only: bool,
    verbose: bool,
) -> ScanReport:

    commits = get_commits(repo, branch, limit, subdir)
    print(f"{BOLD}Scanning {len(commits)} commits in {repo} ({branch}){RESET}")
    if subdir:
        print(f"  Restricted to: {subdir}")
    print()

    report = ScanReport(
        repo=str(repo),
        branch=branch,
        subdir=subdir or "",
        scanned_commits=0,
        scanned_files=0,
        total_file_scans=0,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    # Cache: (sha, filepath) -> FileScanResult  (avoid re-scanning same tree)
    scan_cache: Dict[Tuple[str, str], FileScanResult] = {}

    # Active bugs: (filepath, bug_type) -> BugLifetime
    active_bugs: Dict[Tuple[str, str], BugLifetime] = {}

    def cached_scan(sha: str, filepath: str, content: Optional[str]) -> FileScanResult:
        key = (sha, filepath)
        if key not in scan_cache:
            if content is None:
                scan_cache[key] = FileScanResult(verdict="MISSING")
            else:
                scan_cache[key] = scan_content(content, filepath, use_cli, timeout_ms)
            report.total_file_scans += 1
        return scan_cache[key]

    for idx, commit in enumerate(commits):
        sha   = commit["sha"]
        short = commit["short"]
        date  = commit["date"][:10]
        msg   = commit["msg"]

        changed = get_changed_python_files(repo, sha, subdir)
        if not changed:
            continue

        parent_sha = get_parent_sha(repo, sha)
        report.scanned_commits += 1

        print(f"[{idx+1:>3}/{len(commits)}] {CYAN}{short}{RESET} {date}  "
              f"{msg[:60]}  ({len(changed)} .py files)")

        for filepath in changed:
            report.scanned_files += 1

            after_content  = get_file_at_commit(repo, sha, filepath)
            before_content = (
                get_file_at_commit(repo, parent_sha, filepath)
                if parent_sha else None
            )

            after_result  = cached_scan(sha, filepath, after_content)
            before_result = (
                cached_scan(parent_sha, filepath, before_content)
                if parent_sha else FileScanResult(verdict="MISSING")
            )

            # Determine event
            before_is_bug = before_result.verdict == "BUG"
            after_is_bug  = after_result.verdict  == "BUG"

            if not before_is_bug and after_is_bug:
                event = "BUG_INTRODUCED"
            elif before_is_bug and not after_is_bug:
                event = "BUG_FIXED"
            elif before_is_bug and after_is_bug:
                event = "PERSISTS"
            else:
                event = "CLEAN"

            before_types = set(before_result.bug_types)
            after_types  = set(after_result.bug_types)
            new_types    = sorted(after_types  - before_types)
            fixed_types  = sorted(before_types - after_types)

            if events_only and event == "CLEAN":
                continue

            ev = CommitFileEvent(
                commit_sha=sha,
                commit_short=short,
                commit_date=commit["date"],
                commit_msg=msg,
                author=commit["author"],
                filepath=filepath,
                event=event,
                before=before_result,
                after=after_result,
                new_bug_types=new_types,
                fixed_bug_types=fixed_types,
            )
            report.events.append(ev)

            # Update lifetime tracking
            for bt in new_types:
                key = (filepath, bt)
                active_bugs[key] = BugLifetime(
                    filepath=filepath,
                    bug_type=bt,
                    introduced_sha=short,
                    introduced_date=date,
                    introduced_msg=msg,
                )
            for bt in fixed_types:
                key = (filepath, bt)
                if key in active_bugs:
                    lf = active_bugs.pop(key)
                    lf.fixed_sha   = short
                    lf.fixed_date  = date
                    lf.fixed_msg   = msg
                    lf.still_present = False
                    report.lifetimes.append(lf)
                else:
                    # Fixed at this commit but introduced before scan window
                    report.lifetimes.append(BugLifetime(
                        filepath=filepath,
                        bug_type=bt,
                        introduced_sha="<before-scan-window>",
                        introduced_date="",
                        introduced_msg="",
                        fixed_sha=short,
                        fixed_date=date,
                        fixed_msg=msg,
                        still_present=False,
                    ))

            # Live logging
            colour = {
                "BUG_INTRODUCED": RED,
                "BUG_FIXED":      GREEN,
                "PERSISTS":       YELLOW,
                "CLEAN":          "",
            }.get(event, "")
            if verbose or event != "CLEAN":
                slug = filepath.split("/")[-1]
                print(f"    {colour}{event:<16}{RESET} {slug}"
                      + (f"  +{new_types}"   if new_types   else "")
                      + (f"  -{fixed_types}" if fixed_types else ""))

    # Any bug still in active_bugs was never fixed within the scan window
    for (filepath, bt), lf in active_bugs.items():
        lf.still_present = True
        report.lifetimes.append(lf)

    # Count commits_alive for each lifetime
    sha_index = {c["short"]: i for i, c in enumerate(commits)}
    for lf in report.lifetimes:
        intro_i = sha_index.get(lf.introduced_sha, len(commits) - 1)
        fixed_i = sha_index.get(lf.fixed_sha,   0) if lf.fixed_sha else 0
        lf.commits_alive = max(0, intro_i - fixed_i)

    return report


# ═══════════════════════════════════════════════════════════════════════════
# Report rendering
# ═══════════════════════════════════════════════════════════════════════════

def render_summary(report: ScanReport) -> str:
    introduced = [e for e in report.events if e.event == "BUG_INTRODUCED"]
    fixed      = [e for e in report.events if e.event == "BUG_FIXED"]
    persists   = [e for e in report.events if e.event == "PERSISTS"]
    still_open = [lf for lf in report.lifetimes if lf.still_present]

    lines = [
        "",
        f"{BOLD}{'='*70}{RESET}",
        f"{BOLD}  BUG HISTORY SUMMARY{RESET}",
        f"{'='*70}",
        f"  Repository  : {report.repo}",
        f"  Branch      : {report.branch}",
        f"  Commits     : {report.scanned_commits}  (of {report.scanned_commits} with .py changes)",
        f"  File scans  : {report.total_file_scans}  ({report.scanned_files} unique file×commit pairs)",
        f"",
        f"  {RED}BUG_INTRODUCED{RESET}  : {len(introduced)}",
        f"  {GREEN}BUG_FIXED{RESET}      : {len(fixed)}",
        f"  {YELLOW}PERSISTS{RESET}       : {len(persists)}",
        f"  Open bugs   : {len(still_open)}",
        f"{'='*70}",
    ]

    if still_open:
        lines.append(f"\n{RED}Still-open bugs (not fixed within scan window):{RESET}")
        for lf in sorted(still_open, key=lambda x: x.introduced_date, reverse=True):
            lines.append(f"  [{lf.introduced_date}] {lf.bug_type:25} in {lf.filepath}")

    if fixed:
        lines.append(f"\n{GREEN}Fixed bugs:{RESET}")
        for lf in sorted(
            [lf for lf in report.lifetimes if not lf.still_present],
            key=lambda x: x.fixed_date or ""
        ):
            age = f"{lf.commits_alive}c" if lf.commits_alive else "?"
            lines.append(
                f"  {lf.introduced_date} → {lf.fixed_date}  "
                f"({age})  {lf.bug_type:25} in {lf.filepath.split('/')[-1]}"
            )

    lines.append("")
    return "\n".join(lines)


def render_markdown(report: ScanReport) -> str:
    introduced = [e for e in report.events if e.event == "BUG_INTRODUCED"]
    fixed      = [e for e in report.events if e.event == "BUG_FIXED"]
    persists   = [e for e in report.events if e.event == "PERSISTS"]
    still_open = [lf for lf in report.lifetimes if lf.still_present]
    fixed_lfs  = [lf for lf in report.lifetimes if not lf.still_present]

    md = textwrap.dedent(f"""\
    # a3-python Bug History Report

    **Repository:** `{report.repo}`
    **Branch:** `{report.branch}`
    **Generated:** {report.generated_at}

    ## Summary

    | Metric | Count |
    |--------|------:|
    | Commits scanned | {report.scanned_commits} |
    | File×commit scans | {report.total_file_scans} |
    | Bugs introduced | {len(introduced)} |
    | Bugs fixed | {len(fixed)} |
    | Persistent findings | {len(persists)} |
    | Still open | {len(still_open)} |

    """)

    if still_open:
        md += "## Still-Open Bugs\n\n"
        md += "| Introduced | Bug Type | File |\n"
        md += "|------------|----------|------|\n"
        for lf in sorted(still_open, key=lambda x: x.introduced_date, reverse=True):
            fname = lf.filepath.split("/")[-1]
            md += f"| {lf.introduced_date} | `{lf.bug_type}` | `{fname}` |\n"
        md += "\n"

    if fixed_lfs:
        md += "## Fixed Bugs\n\n"
        md += "| Introduced | Fixed | Lifetime | Bug Type | File |\n"
        md += "|------------|-------|----------|----------|------|\n"
        for lf in sorted(fixed_lfs, key=lambda x: x.fixed_date or ""):
            fname = lf.filepath.split("/")[-1]
            age = f"{lf.commits_alive} commits" if lf.commits_alive else "?"
            md += (f"| {lf.introduced_date} | {lf.fixed_date} | {age} "
                   f"| `{lf.bug_type}` | `{fname}` |\n")
        md += "\n"

    if report.events:
        md += "## Event Timeline\n\n"
        md += "| Commit | Date | Event | Bug Types | File |\n"
        md += "|--------|------|-------|-----------|------|\n"
        for ev in report.events:
            if ev.event == "CLEAN":
                continue
            bt_str = ", ".join(
                f"`{t}`" for t in (ev.new_bug_types or ev.fixed_bug_types
                                   or ev.after.bug_types or ev.before.bug_types)
            ) or "—"
            fname = ev.filepath.split("/")[-1]
            md += (f"| `{ev.commit_short}` | {ev.commit_date[:10]} "
                   f"| **{ev.event}** | {bt_str} | `{fname}` |\n")
        md += "\n"

    return md


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Scan the git history of the top Python repos on GitHub with a3-python."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Prerequisites")[0].rstrip(),
    )
    # ── GitHub discovery ────────────────────────────────────────────────────
    p.add_argument("--num-repos", type=int, default=20,
                   help="Number of top Python repos to scan (default: 20)")
    p.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""),
                   metavar="TOKEN",
                   help="GitHub personal-access token (or set $GITHUB_TOKEN). "
                        "Avoids rate-limiting.")
    p.add_argument("--workdir", default=str(DEFAULT_WORKDIR),
                   help=f"Directory where repos are cloned (default: {DEFAULT_WORKDIR})")
    # ── Scan options ────────────────────────────────────────────────────────
    p.add_argument("--limit",   type=int, default=1000,
                   help="Maximum commits to inspect per repo (default: 1000)")
    p.add_argument("--subdir",  default="",
                   help="Restrict to Python files under this subdirectory")
    p.add_argument("--out",     default="results/bug_history.json",
                   help="Path for combined JSON output (default: results/bug_history.json)")
    p.add_argument("--report",  default="results/bug_history.md",
                   help="Path for Markdown report (default: results/bug_history.md)")
    p.add_argument("--timeout-ms", type=int, default=15_000,
                   help="a3 analysis timeout per file in ms (default: 15000)")
    p.add_argument("--use-cli", action="store_true",
                   help="Use the `a3` CLI instead of the Python API")
    p.add_argument("--events-only", action="store_true",
                   help="Only record commits where bug status changed")
    p.add_argument("--verbose", action="store_true",
                   help="Print CLEAN events too")
    p.add_argument("--no-save", action="store_true",
                   help="Skip writing output files (print to stdout only)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    # ── 1. Discover top Python repos ────────────────────────────────────────
    print(f"{BOLD}Fetching top {args.num_repos} Python repositories from GitHub …{RESET}")
    repos = fetch_top_python_repos(n=args.num_repos, token=args.github_token or None)
    print(f"Found {len(repos)} repos:\n")
    for i, r in enumerate(repos, 1):
        stars = f"{r['stargazers_count']:,}"
        print(f"  {i:>2}. {r['full_name']:<40}  ★ {stars}")
    print()

    # ── 2. Clone / update each repo, then scan ──────────────────────────────
    all_reports: List[ScanReport] = []
    failed: List[str] = []

    for i, repo_meta in enumerate(repos, 1):
        full_name = repo_meta["full_name"]
        dest = workdir / full_name.replace("/", "__")
        print(f"{BOLD}[{i}/{len(repos)}] {full_name}{RESET}")

        ok = clone_or_update_repo(repo_meta["clone_url"], dest)
        if not ok:
            print(f"  {RED}Skipping {full_name} (clone/fetch failed){RESET}")
            failed.append(full_name)
            continue

        report = scan_history(
            repo=dest,
            branch=repo_meta["default_branch"],
            limit=args.limit,
            subdir=args.subdir,
            use_cli=args.use_cli,
            timeout_ms=args.timeout_ms,
            events_only=args.events_only,
            verbose=args.verbose,
        )
        all_reports.append(report)
        print(render_summary(report))

    # ── 3. Aggregate summary across all repos ───────────────────────────────
    total_introduced = sum(
        sum(1 for e in r.events if e.event == "BUG_INTRODUCED") for r in all_reports
    )
    total_fixed = sum(
        sum(1 for e in r.events if e.event == "BUG_FIXED") for r in all_reports
    )
    total_open = sum(
        sum(1 for lf in r.lifetimes if lf.still_present) for r in all_reports
    )
    total_commits = sum(r.scanned_commits for r in all_reports)
    total_scans   = sum(r.total_file_scans for r in all_reports)

    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  COMBINED SUMMARY  ({len(all_reports)} repos){RESET}")
    print(f"{'='*70}")
    print(f"  Repos scanned   : {len(all_reports)}/{len(repos)}")
    print(f"  Commits scanned : {total_commits}")
    print(f"  File scans      : {total_scans}")
    print(f"  {RED}BUG_INTRODUCED{RESET}  : {total_introduced}")
    print(f"  {GREEN}BUG_FIXED{RESET}      : {total_fixed}")
    print(f"  Open bugs       : {total_open}")
    if failed:
        print(f"  {YELLOW}Failed repos{RESET}    : {', '.join(failed)}")
    print(f"{'='*70}\n")

    # ── 4. Save combined output ──────────────────────────────────────────────
    if not args.no_save and all_reports:
        out_json = Path(args.out)
        out_md   = Path(args.report)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_md.parent.mkdir(parents=True, exist_ok=True)

        combined = [asdict(r) for r in all_reports]
        with out_json.open("w") as f:
            json.dump(combined, f, indent=2, default=str)
        print(f"JSON  → {out_json}")

        md_sections = []
        for r in all_reports:
            md_sections.append(render_markdown(r))
        with out_md.open("w") as f:
            f.write("\n\n---\n\n".join(md_sections))
        print(f"MD    → {out_md}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
