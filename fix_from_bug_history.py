#!/usr/bin/env python3
"""
fix_from_bug_history.py  —  Copilot-driven a3-python calibration
==================================================================

Reads results/bug_history.md, extracts every BUG_INTRODUCED and BUG_FIXED
event, fetches the real git diff from the local cloned repos, and sends each
diff to GitHub Copilot asking:

  "Was this actually a bug introduction / bug fix, or a false positive?"

After verifying all events it:
  1. Prints a per-bug-type accuracy table
  2. For each false-positive pattern, asks Copilot to suggest a targeted
     improvement to the corresponding a3-python checker
  3. Writes those suggestions as real diffs / code edits into the a3_python/
     unsafe/ and a3_python/semantics/ trees, with a complete change log at
     results/a3_calibration.md

Usage
-----
  # Auth is handled by the GitHub CLI \u2014 run `gh auth login` once first.
  python fix_from_bug_history.py

  python fix_from_bug_history.py \\
      --history results/bug_history.md \\
      --workdir /tmp/a3_top_python_repos \\
      --out results/a3_calibration.md \\
      --apply                  # actually write edits to a3_python/

  # Use a different GitHub Models model
  python fix_from_bug_history.py --model claude-3.5-sonnet

Prerequisites
-------------
  gh CLI installed and authenticated:
    brew install gh && gh auth login
  (GitHub Models access is included with any GitHub Copilot subscription)

Notes
-----
  • Each diff is truncated to 4 000 characters before sending to avoid
    exceeding the model context window.
  • The script skips events whose commit SHA cannot be resolved in the local
    clone (e.g. a shallow clone that was not deep enough).
  • All LLM responses are cached in results/.copilot_cache.json so re-runs
    are cheap and do not hit the API again for already-reviewed diffs.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import textwrap
import time
import hashlib
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── locate a3-python ─────────────────────────────────────────────────────────
A3_ROOT = Path(__file__).resolve().parent
if str(A3_ROOT) not in sys.path:
    sys.path.insert(0, str(A3_ROOT))

_TTY   = sys.stdout.isatty()
RED    = "\033[31m" if _TTY else ""
GREEN  = "\033[32m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN   = "\033[36m" if _TTY else ""
BOLD   = "\033[1m"  if _TTY else ""
RESET  = "\033[0m"  if _TTY else ""

DEFAULT_HISTORY = Path("results/bug_history.md")
DEFAULT_WORKDIR = Path("/tmp/a3_top_python_repos")
DEFAULT_OUT     = Path("results/a3_calibration.md")
CACHE_PATH      = Path("results/.copilot_cache.json")

MAX_DIFF_CHARS  = 4_000   # chars sent to LLM per diff
MAX_FILE_CHARS  = 2_000   # chars of full-file context (before + after)


# ═══════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class HistoryEvent:
    repo_full_name: str          # e.g. "django/django"
    repo_path: Path              # local clone dir (set later)
    commit_short: str
    date: str
    event: str                   # BUG_INTRODUCED | BUG_FIXED
    bug_types: List[str]
    filename: str


@dataclass
class VerificationResult:
    event: HistoryEvent
    diff: str
    is_real: bool                # Copilot's verdict
    confidence: float            # 0.0 – 1.0
    reasoning: str
    suggestion: str = ""         # Copilot's suggested a3-python change (if FP/FN)
    applied_file: str = ""       # path that was edited, if --apply
    raw_response: str = ""


@dataclass
class BugTypeStats:
    bug_type: str
    total: int = 0
    true_positive: int = 0
    false_positive: int = 0
    examples: List[VerificationResult] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.true_positive / self.total if self.total else 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Markdown parser
# ═══════════════════════════════════════════════════════════════════════════

_REPO_RE   = re.compile(r"\*\*Repository:\*\*\s+`?([^`\n]+)`?")
# Event Timeline row: | `abc1234` | 2024-01-01 | **BUG_INTRODUCED** | `TYPE` | `file.py` |
_EVENT_RE  = re.compile(
    r"\|\s*`([0-9a-f]{6,40})`\s*\|"    # commit short
    r"\s*([\d\-]{10})\s*\|"            # date
    r"\s*\*\*(BUG_INTRODUCED|BUG_FIXED)\*\*\s*\|"  # event
    r"\s*(.*?)\s*\|"                   # bug_types cell
    r"\s*`([^`]+)`\s*\|"              # filename
)
_BACKTICK_RE = re.compile(r"`([^`]+)`")


def parse_history_md(path: Path) -> List[HistoryEvent]:
    """Parse bug_history.md (may contain multiple repo sections)."""
    text = path.read_text(encoding="utf-8")
    sections = re.split(r"\n---\n", text)

    events: List[HistoryEvent] = []
    for section in sections:
        repo_m = _REPO_RE.search(section)
        if not repo_m:
            continue
        repo_raw = repo_m.group(1).strip()
        # Keep absolute local paths as-is; only normalise owner/repo-style names.
        if Path(repo_raw).is_absolute():
            repo_full_name = repo_raw
        else:
            parts = Path(repo_raw).parts
            if len(parts) >= 2 and not repo_raw.startswith("http"):
                repo_full_name = "/".join(parts[-2:])
            else:
                repo_full_name = repo_raw

        for m in _EVENT_RE.finditer(section):
            commit_short = m.group(1)
            date         = m.group(2)
            event_type   = m.group(3)
            types_cell   = m.group(4)
            filename     = m.group(5)

            bug_types = _BACKTICK_RE.findall(types_cell)
            if not bug_types:
                bug_types = [t.strip() for t in types_cell.split(",") if t.strip() and t.strip() != "—"]

            events.append(HistoryEvent(
                repo_full_name=repo_full_name,
                repo_path=Path(),            # filled in by resolve_repo_paths()
                commit_short=commit_short,
                date=date,
                event=event_type,
                bug_types=bug_types or ["UNKNOWN"],
                filename=filename,
            ))

    return events


_NOT_FOUND = Path("__NOT_FOUND__")   # sentinel – never a real path


def resolve_repo_paths(events: List[HistoryEvent], workdir: Path) -> None:
    """Map each event's repo_full_name to a local clone path.

    Handles three cases:
    1. repo_full_name is an absolute local path that exists (scan was run with --repo .)
    2. repo_full_name looks like owner/repo and the slug dir exists under workdir
    3. workdir doesn't exist at all (gracefully marks as not found)
    """
    cache: Dict[str, Path] = {}
    workdir_children: Optional[List[Path]] = None  # lazy-loaded

    def _workdir_entries() -> List[Path]:
        nonlocal workdir_children
        if workdir_children is None:
            workdir_children = list(workdir.iterdir()) if workdir.exists() else []
        return workdir_children

    for ev in events:
        if ev.repo_full_name in cache:
            ev.repo_path = cache[ev.repo_full_name]
            continue

        # Case 1: the recorded repo value is already a valid local path
        as_path = Path(ev.repo_full_name)
        if as_path.is_absolute() and (as_path / ".git").exists():
            result = as_path
        else:
            # Case 2: look for owner__repo dir under workdir
            slug = ev.repo_full_name.replace("/", "__")
            candidate = workdir / slug
            if candidate.exists():
                result = candidate
            else:
                # case-insensitive fallback scan
                for d in _workdir_entries():
                    if d.name.lower() == slug.lower():
                        result = d
                        break
                else:
                    result = _NOT_FOUND

        cache[ev.repo_full_name] = result
        ev.repo_path = result


# ═══════════════════════════════════════════════════════════════════════════
# Git helpers
# ═══════════════════════════════════════════════════════════════════════════

def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(
        ["git", "-C", str(repo)] + list(args),
        capture_output=True, text=True
    )
    return r.stdout.strip() if r.returncode == 0 else ""


def resolve_short_sha(repo: Path, short: str) -> Optional[str]:
    """Turn a 7-char short SHA into a full SHA, or None if not found."""
    full = _git(repo, "rev-parse", "--verify", short)
    return full if full else None


def get_diff(repo: Path, sha: str, filepath: str) -> str:
    """Return the unified diff for one file at one commit."""
    diff = _git(repo, "show", "--unified=5", "--no-color",
                f"--", sha, "--", filepath)
    if not diff:
        # Fallback: show full commit diff (no specific file)
        diff = _git(repo, "show", "--unified=5", "--no-color", sha)
    return diff[:MAX_DIFF_CHARS * 2]   # pre-truncate before trimming


def get_file_before_after(repo: Path, sha: str, filepath: str) -> Tuple[str, str]:
    """Return (before, after) file snippets around the changed lines."""
    parent = _git(repo, "rev-parse", "--verify", f"{sha}^")
    before = ""
    after  = ""
    if parent:
        r = subprocess.run(
            ["git", "-C", str(repo), "show", f"{parent}:{filepath}"],
            capture_output=True, text=True
        )
        before = r.stdout[:MAX_FILE_CHARS] if r.returncode == 0 else ""
    r = subprocess.run(
        ["git", "-C", str(repo), "show", f"{sha}:{filepath}"],
        capture_output=True, text=True
    )
    after = r.stdout[:MAX_FILE_CHARS] if r.returncode == 0 else ""
    return before, after


# ═══════════════════════════════════════════════════════════════════════════
# LLM client — delegates to `gh api` (GitHub CLI, uses gh auth credentials)
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# LLM client — GitHub Models API, authenticated via `gh auth token`
# ═══════════════════════════════════════════════════════════════════════════

MODELS_URL = "https://models.inference.ai.azure.com/chat/completions"
DEFAULT_MODEL = "gpt-4o"


def _check_gh_auth() -> bool:
    """Return True if `gh auth status` succeeds (user is logged in)."""
    r = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    return r.returncode == 0


def _gh_token() -> str:
    """Return the active GitHub OAuth token via `gh auth token`."""
    r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            "`gh auth token` failed — run `gh auth login` first.\n"
            + r.stderr.strip()
        )
    return r.stdout.strip()


class LLMClient:
    """
    Calls the GitHub Models API (models.inference.ai.azure.com) using the
    OAuth token managed by the GitHub CLI (`gh auth token`).

    No API keys needed in code — `gh auth login` handles everything.
    """

    def __init__(self, model: str = DEFAULT_MODEL, hostname: str = "", verbose: bool = False):
        self.model   = model
        self.verbose = verbose
        if not _check_gh_auth():
            print(
                f"{YELLOW}WARNING: `gh auth status` failed.\n"
                f"  Run `gh auth login` before using this script.{RESET}",
                file=sys.stderr,
            )
        self._token: Optional[str] = None   # lazily fetched

    def _get_token(self) -> str:
        if not self._token:
            self._token = _gh_token()
        return self._token

    def chat(self, messages: List[dict], temperature: float = 0.1) -> str:
        """Send messages to GitHub Models API and return the reply text."""
        token = self._get_token()
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 1024,
        }).encode()

        req = urllib.request.Request(MODELS_URL, data=payload, method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")

        if self.verbose:
            print(f"    [LLM] POST {MODELS_URL} model={self.model}", file=sys.stderr)

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode())
            return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {body[:400]}")


# ═══════════════════════════════════════════════════════════════════════════
# Prompt builders
# ═══════════════════════════════════════════════════════════════════════════

def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    half = n // 2
    return s[:half] + f"\n… [{len(s)-n} chars omitted] …\n" + s[-half:]


VERIFY_SYSTEM = """\
You are a senior security and software-quality engineer reviewing automated \
static-analysis results from a tool called a3-python.

a3-python reports BUG_INTRODUCED (a new bug appeared in a commit) or \
BUG_FIXED (a bug was removed) based on symbolic execution and unsafe-predicate \
checking.

Your job:
1. Read the git diff carefully.
2. Decide whether a3's verdict matches what ACTUALLY happened in the commit.
3. Respond ONLY with a JSON object (no markdown fences) with keys:
   - "is_real":     true  if a3 is correct, false if it is a false positive/negative
   - "confidence":  0.0–1.0
   - "reasoning":   ≤3 sentences explaining your verdict
   - "false_positive_pattern":  (only when is_real=false) A concise label for
     the kind of false positive, e.g. "refactor-only rename" or
     "test-code flagged as prod bug".
"""

VERIFY_USER_TMPL = """\
Repository: {repo}
File:       {filepath}
Commit:     {sha}  ({date})
a3 verdict: {event}
Bug types:  {bug_types}

=== GIT DIFF (truncated to {n} chars) ===
{diff}
"""


FIX_SYSTEM = """\
You are a Python static-analysis expert helping improve a3-python, a symbolic \
execution tool that detects security bugs.

The code for a3-python bug detection live in a3_python/, and is based on a deep semantic barrier analysis of python code (see docs/).
Each detector exports a function with signature:
    check_<name>(paths: List[SymbolicPath], ...) -> List[Finding]

Your job is to write a targeted, minimal Python patch that:
  1. Does NOT break true positives.
  2. Suppresses the described false-positive pattern.
  3. Uses only the Python standard library + z3.
  4. Is not based on surface pattern matching, but on a deep, thorough understanding of the technology behind a3-python and its interactions with z3.

Respond ONLY with a JSON object (no markdown fences) with keys:
  - "target_file":   "a3_python/unsafe/<checker>.py"   (relative to repo root)
  - "description":   ≤2 sentences describing the change
  - "diff":          A unified diff string (--- a/...  +++ b/...) for the change
  - "confidence":    0.0–1.0  (how confident you are the patch is correct)
"""

FIX_USER_TMPL = """\
Checker:              {bug_types}
False-positive label: {fp_label}
Number of FP examples seen: {count}

Representative diff where a3-python incorrectly fired:
{diff}

Current checker source (a3_python/unsafe/ excerpt):
{checker_src}
"""


# ═══════════════════════════════════════════════════════════════════════════
# LLM response parsing
# ═══════════════════════════════════════════════════════════════════════════

def _extract_json(text: str) -> dict:
    """Extract the first JSON object from an LLM response."""
    # Strip markdown code fences if present
    clean = re.sub(r"```(?:json)?", "", text).strip()
    # Find the outermost { ... }
    start = clean.find("{")
    end   = clean.rfind("}")
    if start == -1 or end == -1:
        return {}
    try:
        return json.loads(clean[start:end+1])
    except json.JSONDecodeError:
        return {}


# ═══════════════════════════════════════════════════════════════════════════
# Cache
# ═══════════════════════════════════════════════════════════════════════════

def cache_key(event: HistoryEvent) -> str:
    raw = f"{event.repo_full_name}:{event.commit_short}:{event.filename}:{event.event}"
    return hashlib.sha1(raw.encode()).hexdigest()


def load_cache(path: Path) -> Dict[str, dict]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_cache(path: Path, cache: Dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# Verification loop
# ═══════════════════════════════════════════════════════════════════════════

def verify_events(
    events: List[HistoryEvent],
    client: LLMClient,
    cache: Dict[str, dict],
    verbose: bool = False,
) -> List[VerificationResult]:
    results: List[VerificationResult] = []

    for idx, ev in enumerate(events):
        print(f"  [{idx+1:>4}/{len(events)}] {CYAN}{ev.commit_short}{RESET}  "
              f"{ev.event:<16}  {ev.filename}  "
              f"({', '.join(ev.bug_types)})")

        if not ev.repo_path or ev.repo_path == _NOT_FOUND:
            print(f"    {YELLOW}SKIP: repo not found for '{ev.repo_full_name}'{RESET}")
            continue

        # Resolve short SHA
        full_sha = resolve_short_sha(ev.repo_path, ev.commit_short)
        if not full_sha:
            print(f"    {YELLOW}SKIP: SHA {ev.commit_short} not found in "
                  f"{ev.repo_path.name}{RESET}")
            continue

        ck = cache_key(ev)

        if ck in cache:
            raw_json = cache[ck]
            if verbose:
                print(f"    (cached) is_real={raw_json.get('is_real')}")
        else:
            diff = get_diff(ev.repo_path, full_sha, ev.filename)
            if not diff:
                print(f"    {YELLOW}SKIP: no diff available{RESET}")
                continue

            diff_trunc = _truncate(diff, MAX_DIFF_CHARS)
            user_msg = VERIFY_USER_TMPL.format(
                repo=ev.repo_full_name,
                filepath=ev.filename,
                sha=ev.commit_short,
                date=ev.date,
                event=ev.event,
                bug_types=", ".join(ev.bug_types),
                n=MAX_DIFF_CHARS,
                diff=diff_trunc,
            )
            try:
                raw_text = client.chat([
                    {"role": "system", "content": VERIFY_SYSTEM},
                    {"role": "user",   "content": user_msg},
                ])
                raw_json = _extract_json(raw_text)
                raw_json["_raw"] = raw_text
                raw_json["_diff"] = diff_trunc
                cache[ck] = raw_json
            except Exception as exc:
                print(f"    {RED}LLM error: {exc}{RESET}")
                continue

        is_real    = bool(raw_json.get("is_real", True))
        confidence = float(raw_json.get("confidence", 0.5))
        reasoning  = str(raw_json.get("reasoning", ""))
        diff_used  = raw_json.get("_diff", "")

        colour = GREEN if is_real else RED
        verdict_str = "TRUE_POS" if is_real else "FALSE_POS"
        print(f"    {colour}{verdict_str}{RESET}  (conf={confidence:.2f})  {reasoning[:80]}")

        results.append(VerificationResult(
            event=ev,
            diff=diff_used,
            is_real=is_real,
            confidence=confidence,
            reasoning=reasoning,
            raw_response=raw_json.get("_raw", ""),
        ))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Per-bug-type stats
# ═══════════════════════════════════════════════════════════════════════════

def compute_stats(results: List[VerificationResult]) -> Dict[str, BugTypeStats]:
    stats: Dict[str, BugTypeStats] = {}
    for r in results:
        for bt in r.event.bug_types:
            if bt not in stats:
                stats[bt] = BugTypeStats(bug_type=bt)
            s = stats[bt]
            s.total += 1
            if r.is_real:
                s.true_positive += 1
            else:
                s.false_positive += 1
                s.examples.append(r)
    return stats


# ═══════════════════════════════════════════════════════════════════════════
# Fix generation
# ═══════════════════════════════════════════════════════════════════════════

def _load_checker_src(bug_type: str) -> str:
    """Try to load the source of the a3-python checker for a bug type."""
    # Map bug type string to file name heuristically
    bt = bug_type.lower().replace("_", "")
    candidates = [
        A3_ROOT / "a3_python" / "unsafe" / f"{bug_type.lower()}.py",
        A3_ROOT / "a3_python" / "unsafe" / f"{bt}.py",
        A3_ROOT / "a3_python" / "unsafe" / "exception_bugs.py",
        A3_ROOT / "a3_python" / "semantics" / "interprocedural_bugs.py",
    ]
    for c in candidates:
        if c.exists():
            src = c.read_text(encoding="utf-8", errors="replace")
            return _truncate(src, MAX_FILE_CHARS * 2), str(c.relative_to(A3_ROOT))
    return "", ""


def generate_fixes(
    stats: Dict[str, BugTypeStats],
    client: LLMClient,
    cache: Dict[str, dict],
    verbose: bool = False,
) -> List[dict]:
    """Ask Copilot for a fix for each bug type with false positives."""
    fixes: List[dict] = []
    for bt, s in stats.items():
        if s.false_positive == 0:
            continue
        print(f"\n  Generating fix for {YELLOW}{bt}{RESET}  "
              f"({s.false_positive} FP / {s.total} total) …")

        # Group FPs by their stated label
        fp_labels: Dict[str, list] = defaultdict(list)
        for ex in s.examples:
            label = _extract_json(ex.raw_response).get("false_positive_pattern",
                                                        "unspecified pattern")
            fp_labels[str(label)].append(ex)

        for label, exs in fp_labels.items():
            fix_key = f"fix:{bt}:{label}"
            if fix_key in cache:
                raw_json = cache[fix_key]
                print(f"    (cached fix for '{label}')")
            else:
                checker_src, _ = _load_checker_src(bt)
                representative = exs[0]
                user_msg = FIX_USER_TMPL.format(
                    bug_types=bt,
                    fp_label=label,
                    count=len(exs),
                    diff=_truncate(representative.diff, MAX_DIFF_CHARS),
                    checker_src=_truncate(checker_src, MAX_FILE_CHARS),
                )
                try:
                    raw_text = client.chat([
                        {"role": "system", "content": FIX_SYSTEM},
                        {"role": "user",   "content": user_msg},
                    ])
                    raw_json = _extract_json(raw_text)
                    raw_json["_raw"] = raw_text
                    raw_json["_bug_type"] = bt
                    raw_json["_fp_label"] = label
                    raw_json["_fp_count"] = len(exs)
                    cache[fix_key] = raw_json
                except Exception as exc:
                    print(f"    {RED}LLM error: {exc}{RESET}")
                    continue

            conf = raw_json.get("confidence", 0.0)
            desc = raw_json.get("description", "")
            tgt  = raw_json.get("target_file", "")
            print(f"    {GREEN}Fix{RESET} → {tgt}  (conf={conf})  {desc[:80]}")
            fixes.append(raw_json)

    return fixes


# ═══════════════════════════════════════════════════════════════════════════
# Applying fixes to a3-python source
# ═══════════════════════════════════════════════════════════════════════════

_DIFF_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@",
    re.MULTILINE
)


def apply_unified_diff(repo_root: Path, diff_str: str) -> Optional[str]:
    """
    Apply a unified diff string produced by the LLM.
    Uses `patch -p1` under the hood.
    Returns the path that was patched, or None on failure.
    """
    if not diff_str or "+++" not in diff_str:
        return None

    # Extract target file from +++ line
    target_match = re.search(r"^\+\+\+\s+(?:b/)?(.+?)$", diff_str, re.MULTILINE)
    if not target_match:
        return None
    target_rel = target_match.group(1).strip()
    target_abs = repo_root / target_rel
    if not target_abs.exists():
        return None

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".patch",
                                     delete=False, encoding="utf-8") as pf:
        pf.write(diff_str)
        patch_path = pf.name

    result = subprocess.run(
        ["patch", "-p1", "--forward", "-i", patch_path],
        cwd=str(repo_root), capture_output=True, text=True
    )
    Path(patch_path).unlink(missing_ok=True)

    if result.returncode == 0:
        return target_rel
    # patch(1) failed – return None
    return None


def apply_fixes(fixes: List[dict], repo_root: Path, dry_run: bool = True) -> None:
    if dry_run:
        print(f"\n{YELLOW}(--apply not set; skipping writes){RESET}")
        return

    applied = 0
    for fix in fixes:
        diff_str = fix.get("diff", "")
        if not diff_str:
            continue
        conf = float(fix.get("confidence", 0))
        if conf < 0.6:
            print(f"  {YELLOW}SKIP{RESET} low-confidence fix "
                  f"({conf:.2f}) for {fix.get('_bug_type')} "
                  f"'{fix.get('_fp_label')}'")
            continue
        target = apply_unified_diff(repo_root, diff_str)
        if target:
            fix["_applied_file"] = target
            print(f"  {GREEN}APPLIED{RESET} → {target}")
            applied += 1
        else:
            print(f"  {RED}FAILED{RESET} to apply diff for "
                  f"{fix.get('_bug_type')} '{fix.get('_fp_label')}'")
    print(f"\n  Applied {applied}/{len(fixes)} fixes.")


# ═══════════════════════════════════════════════════════════════════════════
# Report rendering
# ═══════════════════════════════════════════════════════════════════════════

def render_report(
    events: List[HistoryEvent],
    results: List[VerificationResult],
    stats: Dict[str, BugTypeStats],
    fixes: List[dict],
) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    total      = len(results)
    true_pos   = sum(1 for r in results if r.is_real)
    false_pos  = total - true_pos
    overall_p  = true_pos / total if total else 0.0

    lines = [
        "# a3-python Calibration Report",
        "",
        f"**Generated:** {ts}",
        f"**Events reviewed:** {total}",
        f"**True positives:** {true_pos}  ({overall_p:.0%})",
        f"**False positives:** {false_pos}  ({1-overall_p:.0%})",
        "",
        "## Accuracy by Bug Type",
        "",
        "| Bug Type | Total | TP | FP | Precision |",
        "|----------|------:|---:|---:|----------:|",
    ]
    for bt, s in sorted(stats.items(), key=lambda x: x[1].precision):
        lines.append(f"| `{bt}` | {s.total} | {s.true_positive} "
                     f"| {s.false_positive} | {s.precision:.0%} |")

    lines += ["", "## False Positive Examples", ""]
    for r in results:
        if r.is_real:
            continue
        fp_label = _extract_json(r.raw_response).get(
            "false_positive_pattern", "unspecified")
        lines += [
            f"### `{r.event.commit_short}`  {r.event.event}  "
            f"({', '.join(r.event.bug_types)})",
            f"**Repo:** {r.event.repo_full_name}  **File:** `{r.event.filename}`  "
            f"**Date:** {r.event.date}",
            f"**FP Pattern:** {fp_label}",
            f"**Reasoning:** {r.reasoning}",
            "",
            "<details><summary>Diff</summary>",
            "",
            "```diff",
            r.diff[:2000],
            "```",
            "",
            "</details>",
            "",
        ]

    if fixes:
        lines += ["## Proposed a3-python Fixes", ""]
        for fix in fixes:
            conf     = fix.get("confidence", 0)
            tgt      = fix.get("target_file", "?")
            bt       = fix.get("_bug_type", "?")
            fp_label = fix.get("_fp_label", "?")
            desc     = fix.get("description", "")
            diff_str = fix.get("diff", "")
            applied  = fix.get("_applied_file", "")
            status   = f"✅ applied to `{applied}`" if applied else "⚠ not applied"

            lines += [
                f"### {bt} — {fp_label}",
                f"**Target:** `{tgt}`  **Confidence:** {conf:.0%}  **Status:** {status}",
                f"{desc}",
                "",
                "<details><summary>Diff</summary>",
                "",
                "```diff",
                diff_str[:3000],
                "```",
                "",
                "</details>",
                "",
            ]

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Verify a3-python bug-history events with Copilot and update detectors.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--history", default=str(DEFAULT_HISTORY),
                   help=f"Path to bug_history.md (default: {DEFAULT_HISTORY})")
    p.add_argument("--workdir", default=str(DEFAULT_WORKDIR),
                   help=f"Directory with cloned repos (default: {DEFAULT_WORKDIR})")
    p.add_argument("--hostname", default="",
                   metavar="HOST",
                   help="(unused, kept for compatibility)")
    p.add_argument("--model", default=DEFAULT_MODEL,
                   help=f"GitHub Models model name (default: {DEFAULT_MODEL})")
    p.add_argument("--out", default=str(DEFAULT_OUT),
                   help=f"Markdown report output (default: {DEFAULT_OUT})")
    p.add_argument("--cache", default=str(CACHE_PATH),
                   help=f"JSON cache for LLM responses (default: {CACHE_PATH})")
    p.add_argument("--apply", action="store_true",
                   help="Actually write Copilot-suggested fixes to a3_python/ source")
    p.add_argument("--min-confidence", type=float, default=0.6,
                   help="Minimum Copilot confidence to act on (default: 0.6)")
    p.add_argument("--limit-events", type=int, default=0,
                   help="Cap number of events to verify (0 = all, useful for testing)")
    p.add_argument("--verbose", action="store_true",
                   help="Print extra detail")
    p.add_argument("--no-fixes", action="store_true",
                   help="Skip fix-generation step (verify only)")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    history_path = Path(args.history)
    if not history_path.exists():
        print(f"{RED}ERROR: {history_path} not found.  "
              "Run scan_bug_history.py first.{RESET}", file=sys.stderr)
        return 1

    workdir = Path(args.workdir)
    cache_p = Path(args.cache)

    # ── 1. Parse history ──────────────────────────────────────────────────
    print(f"{BOLD}Parsing {history_path} …{RESET}")
    events = parse_history_md(history_path)
    print(f"  Found {len(events)} BUG_INTRODUCED / BUG_FIXED events.")

    resolve_repo_paths(events, workdir)
    found_repos = sum(1 for e in events if e.repo_path and e.repo_path != _NOT_FOUND)
    print(f"  Resolved local clone for {found_repos}/{len(events)} events.")

    if args.limit_events:
        events = events[:args.limit_events]
        print(f"  (capped to {len(events)} events via --limit-events)")

    if not events:
        print(f"{YELLOW}No events to verify.{RESET}")
        return 0

    # ── 2. Build LLM client ───────────────────────────────────────────────
    client = LLMClient(
        model=args.model,
        verbose=args.verbose,
    )
    cache = load_cache(cache_p)

    # ── 3. Verify each event ──────────────────────────────────────────────
    print(f"\n{BOLD}Verifying {len(events)} events with Copilot …{RESET}\n")
    results = verify_events(events, client, cache, verbose=args.verbose)
    save_cache(cache_p, cache)
    print(f"\n  Verified {len(results)} events.  "
          f"Cache saved to {cache_p}.")

    # ── 4. Stats ──────────────────────────────────────────────────────────
    stats = compute_stats(results)
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  ACCURACY SUMMARY{RESET}")
    print(f"{'='*60}")
    for bt, s in sorted(stats.items(), key=lambda x: x[1].precision):
        bar_len = int(s.precision * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        colour = GREEN if s.precision >= 0.8 else (YELLOW if s.precision >= 0.5 else RED)
        print(f"  {bt:<30}  {colour}{bar}{RESET}  "
              f"{s.precision:.0%}  ({s.true_positive}/{s.total})")
    print(f"{'='*60}\n")

    # ── 5. Generate fixes ─────────────────────────────────────────────────
    fixes: List[dict] = []
    if not args.no_fixes:
        print(f"{BOLD}Generating fixes for false-positive patterns …{RESET}")
        fixes = generate_fixes(stats, client, cache, verbose=args.verbose)
        save_cache(cache_p, cache)

    # ── 6. Apply fixes ────────────────────────────────────────────────────
    apply_fixes(fixes, A3_ROOT, dry_run=not args.apply)

    # ── 7. Write report ───────────────────────────────────────────────────
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report_md = render_report(events, results, stats, fixes)
    out_path.write_text(report_md, encoding="utf-8")
    print(f"\n{BOLD}Report → {out_path}{RESET}")

    # ── 8. Print top false positive patterns ──────────────────────────────
    fp_patterns: Dict[str, int] = defaultdict(int)
    for r in results:
        if not r.is_real:
            label = _extract_json(r.raw_response).get(
                "false_positive_pattern", "unspecified")
            fp_patterns[str(label)] += 1
    if fp_patterns:
        print(f"\n{RED}Top false-positive patterns:{RESET}")
        for label, cnt in sorted(fp_patterns.items(), key=lambda x: -x[1]):
            print(f"  {cnt:>4}×  {label}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
