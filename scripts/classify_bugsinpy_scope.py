#!/usr/bin/env python3
"""
Step 1: Classify every BugsInPy bug as IN-SCOPE or OUT-OF-SCOPE for a3-python.

a3-python is a static analyser that detects:
  - Crash bugs:  NULL_PTR, DIV_ZERO, BOUNDS, TYPE_CONFUSION, ASSERT_FAIL,
                 STACK_OVERFLOW, USE_AFTER_FREE, UNINIT_MEMORY, etc.
  - Security:    SQL_INJECTION, COMMAND_INJECTION, XSS, SSRF, PATH_INJECTION,
                 UNSAFE_DESERIALIZATION, etc.
  - Semantic:    UNVALIDATED_INPUT, UNCHECKED_RETURN, USE_BEFORE_INIT,
                 USE_AFTER_CLOSE, ITERATOR_PROTOCOL, etc.
  - Exceptions:  AttributeError, TypeError, KeyError, IndexError, ValueError
                 when they stem from missing guards / type checks.

Out-of-scope:
  - Pure logic / algorithmic bugs (wrong formula, wrong constant)
  - Formatting / string output bugs
  - Performance / optimisation bugs
  - API design changes (adding parameters, renaming)
  - Build/packaging/import reorganisation

This script reads every bug_patch.txt, applies heuristic rules + AST
analysis to classify, then writes:
  - results/bugsinpy_classified.json   (machine-readable)
  - results/bugsinpy_classified.md     (human-readable report)

Usage:
    python scripts/classify_bugsinpy_scope.py
    python scripts/classify_bugsinpy_scope.py --projects ansible black
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

A3_ROOT  = Path(__file__).resolve().parent.parent
BUGS_DIR = A3_ROOT / "BugsInPy" / "projects"

ALL_PROJECTS = sorted(
    d.name for d in BUGS_DIR.iterdir() if d.is_dir()
) if BUGS_DIR.exists() else []

# ═══════════════════════════════════════════════════════════════════════════
# Classification categories
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BugClassification:
    project: str
    bug_id: int
    in_scope: bool
    category: str          # e.g. "null-deref", "type-error", "logic", ...
    confidence: float      # 0.0–1.0  how sure we are about the classification
    a3_bug_type: str       # mapped a3 bug type (e.g. NULL_PTR) or ""
    reason: str            # human-readable explanation
    patch_summary: str     # first 300 chars of the patch
    changed_files: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Patch parsing helpers
# ═══════════════════════════════════════════════════════════════════════════

def _get_patch_text(project: str, bug_id: int) -> str:
    p = BUGS_DIR / project / "bugs" / str(bug_id) / "bug_patch.txt"
    return p.read_text(errors="replace") if p.exists() else ""


def _get_changed_files(patch: str) -> List[str]:
    files = []
    for line in patch.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                f = parts[3].lstrip("b/")
                if f.endswith(".py"):
                    files.append(f)
    return list(dict.fromkeys(files))  # dedupe preserving order


def _added_removed_lines(patch: str) -> Tuple[List[str], List[str]]:
    """Return (added, removed) non-blank code lines from a patch."""
    added, removed = [], []
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            code = line[1:].strip()
            if code and not code.startswith("#"):
                added.append(code)
        elif line.startswith("-") and not line.startswith("---"):
            code = line[1:].strip()
            if code and not code.startswith("#"):
                removed.append(code)
    return added, removed


# ═══════════════════════════════════════════════════════════════════════════
# Classification rules  (ordered: first match wins)
# ═══════════════════════════════════════════════════════════════════════════

def _classify(project: str, bug_id: int, patch: str) -> BugClassification:
    """Heuristic classifier for one BugsInPy bug."""
    lower = patch.lower()
    added, removed = _added_removed_lines(patch)
    added_text = "\n".join(added).lower()
    removed_text = "\n".join(removed).lower()
    all_code = added_text + "\n" + removed_text
    files = _get_changed_files(patch)
    is_test_only = all(
        "test" in f.lower() or f.startswith("test") for f in files
    ) if files else True

    def result(in_scope, category, a3_type, confidence, reason):
        return BugClassification(
            project=project, bug_id=bug_id,
            in_scope=in_scope, category=category,
            confidence=confidence, a3_bug_type=a3_type,
            reason=reason, patch_summary=patch[:300],
            changed_files=files,
        )

    # ── Skip: no patch or test-only ──────────────────────────────────────
    if not patch.strip():
        return result(False, "no-patch", "", 1.0, "No patch file")
    if is_test_only:
        return result(False, "test-only", "", 0.9, "Patch changes test files only")

    # ── IN-SCOPE: Null / None dereference guards ─────────────────────────
    #    Pattern: adding "if X is not None" / "if X is None" / "X is not None"
    none_patterns = [
        r'if\s+\w+\s+is\s+not\s+none',
        r'if\s+\w+\s+is\s+none',
        r'if\s+not\s+\w+',
        r'if\s+\w+\s*!=\s*none',
        r'if\s+\w+\s*==\s*none',
        r'\.get\(',                # dict.get() instead of dict[key]
    ]
    if any(re.search(p, added_text) for p in none_patterns):
        # Check that the added None-guard protects against attribute access
        # or fixes a crash path
        if any(kw in all_code for kw in [
            'attributeerror', '.next', '.prev', 'nonetype',
            'has no attribute', 'cannot ', 'none ',
        ]) or any(re.search(p, added_text) for p in none_patterns[:5]):
            return result(True, "null-deref", "NULL_PTR", 0.85,
                          "Fix adds None/null guard — NULL_PTR class")

    # ── IN-SCOPE: AttributeError ─────────────────────────────────────────
    if 'attributeerror' in lower or 'has no attribute' in lower:
        return result(True, "attribute-error", "NULL_PTR", 0.80,
                      "Fix addresses AttributeError — NULL_PTR class")

    # ── IN-SCOPE: TypeError / type confusion ─────────────────────────────
    if 'typeerror' in lower:
        return result(True, "type-error", "TYPE_CONFUSION", 0.80,
                      "Fix addresses TypeError — TYPE_CONFUSION class")
    if 'isinstance' in added_text and 'isinstance' not in removed_text:
        return result(True, "type-check", "TYPE_CONFUSION", 0.70,
                      "Fix adds isinstance check — TYPE_CONFUSION class")

    # ── IN-SCOPE: KeyError ───────────────────────────────────────────────
    if 'keyerror' in lower:
        return result(True, "key-error", "BOUNDS", 0.75,
                      "Fix addresses KeyError — BOUNDS class")
    # Adding .get() or 'in dict' where [] was used before
    if '.get(' in added_text and ('[' in removed_text):
        return result(True, "key-error", "BOUNDS", 0.65,
                      "Fix replaces dict[] with dict.get() — BOUNDS class")

    # ── IN-SCOPE: IndexError ─────────────────────────────────────────────
    if 'indexerror' in lower:
        return result(True, "index-error", "BOUNDS", 0.80,
                      "Fix addresses IndexError — BOUNDS class")
    # Adding bounds check: len() / "if i < len"
    if re.search(r'if\s+\w+\s*<\s*len\(', added_text):
        return result(True, "bounds-check", "BOUNDS", 0.70,
                      "Fix adds explicit bounds check — BOUNDS class")

    # ── IN-SCOPE: ValueError ─────────────────────────────────────────────
    if 'valueerror' in lower:
        if 'raise valueerror' in added_text:
            return result(True, "value-error", "ASSERT_FAIL", 0.70,
                          "Fix adds ValueError for invalid input — ASSERT_FAIL class")
        return result(True, "value-error", "ASSERT_FAIL", 0.65,
                      "Fix handles ValueError — ASSERT_FAIL class")

    # ── IN-SCOPE: Division by zero ───────────────────────────────────────
    if any(kw in lower for kw in ['zerodivision', 'zero division', 'divide by zero']):
        return result(True, "div-zero", "DIV_ZERO", 0.90,
                      "Fix addresses division by zero — DIV_ZERO class")
    if re.search(r'if\s+\w+\s*[!=]=\s*0', added_text):
        if '/' in all_code or 'divmod' in all_code or '%' in all_code:
            return result(True, "div-zero", "DIV_ZERO", 0.70,
                          "Fix adds zero-check near division — DIV_ZERO class")

    # ── IN-SCOPE: Unhandled exception / missing exception handling ───────
    has_except_added = 'except ' in added_text and 'except ' not in removed_text
    has_raise_added  = 'raise ' in added_text and 'raise ' not in removed_text
    if has_except_added:
        # What exception is being caught?
        for exc, a3type in [
            ('attributeerror', 'NULL_PTR'), ('typeerror', 'TYPE_CONFUSION'),
            ('keyerror', 'BOUNDS'), ('indexerror', 'BOUNDS'),
            ('valueerror', 'ASSERT_FAIL'), ('runtimeerror', 'ASSERT_FAIL'),
            ('filenotfounderror', 'ASSERT_FAIL'), ('oserror', 'ASSERT_FAIL'),
            ('ioerror', 'ASSERT_FAIL'), ('exception', 'ASSERT_FAIL'),
        ]:
            if exc in added_text:
                return result(True, f"unhandled-{exc}", a3type, 0.70,
                              f"Fix adds missing {exc} handler — {a3type} class")
        # Generic except added
        return result(True, "unhandled-exception", "ASSERT_FAIL", 0.55,
                      "Fix adds exception handler — may be in scope")

    # ── IN-SCOPE: Missing validation / assertion ─────────────────────────
    if has_raise_added:
        if any(kw in added_text for kw in [
            'raise ansibleerror', 'raise valueerror', 'raise typeerror',
            'raise runtimeerror', 'raise assertionerror',
        ]):
            return result(True, "missing-validation", "ASSERT_FAIL", 0.65,
                          "Fix raises error for invalid state — ASSERT_FAIL class")

    # ── IN-SCOPE: Injection / security ───────────────────────────────────
    if any(kw in lower for kw in ['sql', 'inject']):
        return result(True, "injection", "SQL_INJECTION", 0.75,
                      "Patch mentions SQL/injection — security class")
    if 'subprocess' in lower and ('shell=true' in lower or 'shell = true' in lower):
        return result(True, "command-injection", "COMMAND_INJECTION", 0.75,
                      "Patch involves subprocess with shell=True — COMMAND_INJECTION")
    if 'eval(' in all_code or 'exec(' in all_code:
        return result(True, "code-injection", "CODE_INJECTION", 0.65,
                      "Patch involves eval/exec — CODE_INJECTION class")

    # ── IN-SCOPE: Resource / iterator bugs ───────────────────────────────
    if 'stopiteration' in lower:
        return result(True, "iterator", "ITERATOR_INVALID", 0.70,
                      "Fix addresses StopIteration — ITERATOR_INVALID class")
    if any(kw in added_text for kw in ['.close()', '__exit__', 'finally:']):
        if any(kw in all_code for kw in ['file', 'open(', 'socket', 'connect']):
            return result(True, "resource-leak", "MEMORY_LEAK", 0.60,
                          "Fix adds resource cleanup — MEMORY_LEAK class")

    # ── IN-SCOPE: Recursion / stack overflow ─────────────────────────────
    if 'recursionerror' in lower or 'maximum recursion' in lower:
        return result(True, "recursion", "STACK_OVERFLOW", 0.80,
                      "Fix addresses recursion — STACK_OVERFLOW class")

    # ── IN-SCOPE: Assertion failure ──────────────────────────────────────
    if 'assertionerror' in lower or 'assert ' in added_text:
        return result(True, "assertion", "ASSERT_FAIL", 0.60,
                      "Patch involves assertions — ASSERT_FAIL class")

    # ── IN-SCOPE: Potential null-deref patterns in fix (no explicit keywords) ──
    #    If the fix adds a guard condition and the removed code had unconditional access
    if re.search(r'^\+\s*if\s+', patch, re.MULTILINE):
        # Check if removed lines have attribute access or subscript on same var
        added_ifs = re.findall(r'^\+\s*if\s+(\w+)', patch, re.MULTILINE)
        for var in added_ifs:
            if re.search(rf'^-.*{re.escape(var)}\.\w+', patch, re.MULTILINE):
                return result(True, "missing-guard", "NULL_PTR", 0.55,
                              f"Fix guards '{var}' before attribute access — NULL_PTR class")
            if re.search(rf'^-.*{re.escape(var)}\[', patch, re.MULTILINE):
                return result(True, "missing-guard", "BOUNDS", 0.55,
                              f"Fix guards '{var}' before subscript — BOUNDS class")

    # ── OUT-OF-SCOPE: Pure logic / algorithmic ───────────────────────────
    # Small patches that just change a value, condition, or return statement
    if len(added) <= 3 and len(removed) <= 3:
        if any(kw in removed_text for kw in ['return ', 'yield ']) and \
           any(kw in added_text for kw in ['return ', 'yield ']):
            return result(False, "logic-return", "", 0.65,
                          "Patch changes return/yield value — likely logic bug")

    # ── OUT-OF-SCOPE: String / formatting bugs ───────────────────────────
    if all(any(kw in l for kw in ['format(', 'f"', "f'", '.strip', '.replace', '%s', '.join']) for l in added[:3]) if added else False:
        return result(False, "string-format", "", 0.60,
                      "Patch changes string formatting — out of scope")

    # ── OUT-OF-SCOPE: Import / reorganisation ────────────────────────────
    if all(l.startswith(('import ', 'from ')) for l in added) and \
       all(l.startswith(('import ', 'from ')) for l in removed):
        return result(False, "import-reorg", "", 0.80,
                      "Patch only changes imports — out of scope")

    # ── Default: uncertain ───────────────────────────────────────────────
    # Check if there's *any* indicator of a crash/exception scenario
    crash_indicators = [
        'error', 'exception', 'raise', 'assert', 'crash', 'fail',
        'none', 'null', 'not found', 'missing', 'invalid',
    ]
    hit_count = sum(1 for kw in crash_indicators if kw in lower)
    if hit_count >= 3:
        return result(True, "possible-crash", "ASSERT_FAIL", 0.40,
                      f"Patch has {hit_count} crash-related keywords — possibly in scope")
    if hit_count >= 1:
        return result(False, "uncertain", "", 0.35,
                      f"Only {hit_count} crash indicator(s) — likely out of scope")

    return result(False, "logic", "", 0.50,
                  "No crash/exception patterns found — likely pure logic bug")


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def classify_all(projects: List[str]) -> List[BugClassification]:
    results = []
    for project in projects:
        bugs_dir = BUGS_DIR / project / "bugs"
        if not bugs_dir.exists():
            continue
        for bug_dir in sorted(bugs_dir.iterdir(), key=lambda d: int(d.name) if d.name.isdigit() else 0):
            if not bug_dir.is_dir() or not bug_dir.name.isdigit():
                continue
            bug_id = int(bug_dir.name)
            patch = _get_patch_text(project, bug_id)
            cl = _classify(project, bug_id, patch)
            results.append(cl)
    return results


def write_report(results: List[BugClassification], out: Path) -> None:
    in_scope  = [r for r in results if r.in_scope]
    out_scope = [r for r in results if not r.in_scope]
    cats = Counter(r.category for r in in_scope)
    a3types = Counter(r.a3_bug_type for r in in_scope if r.a3_bug_type)

    lines = [
        "# BugsInPy Scope Classification for a3-python",
        f"_Generated: {datetime.now().isoformat(timespec='seconds')}_\n",
        "## Summary\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total bugs | {len(results)} |",
        f"| **In-scope** (a3 could/should detect) | **{len(in_scope)}** |",
        f"| Out-of-scope (logic/format/etc.) | {len(out_scope)} |",
        "",
        "## In-Scope Bug Categories\n",
        "| Category | Count | a3 Bug Type |",
        "|----------|-------|-------------|",
    ]
    for cat, cnt in cats.most_common():
        a3t = next((r.a3_bug_type for r in in_scope if r.category == cat), "")
        lines.append(f"| {cat} | {cnt} | {a3t} |")

    lines += [
        "", "## a3 Bug Type Distribution (in-scope only)\n",
        "| a3 Bug Type | Count |",
        "|-------------|-------|",
    ]
    for bt, cnt in a3types.most_common():
        lines.append(f"| {bt} | {cnt} |")

    # Per-project
    proj_stats = defaultdict(lambda: {"in": 0, "out": 0})
    for r in results:
        proj_stats[r.project]["in" if r.in_scope else "out"] += 1
    lines += [
        "", "## Per-Project\n",
        "| Project | In-scope | Out-scope | Total |",
        "|---------|----------|-----------|-------|",
    ]
    for proj in sorted(proj_stats):
        s = proj_stats[proj]
        lines.append(f"| {proj} | {s['in']} | {s['out']} | {s['in']+s['out']} |")

    # In-scope bug list
    lines += ["", "## In-Scope Bugs (detailed)\n",
              "| # | Project | Bug | Category | a3 Type | Conf | Reason |",
              "|---|---------|-----|----------|---------|------|--------|"]
    for i, r in enumerate(in_scope, 1):
        lines.append(
            f"| {i} | {r.project} | {r.bug_id} | {r.category} "
            f"| {r.a3_bug_type} | {r.confidence:.0%} | {r.reason[:60]} |"
        )

    # Out-of-scope summary
    out_cats = Counter(r.category for r in out_scope)
    lines += ["", "## Out-of-Scope Categories\n",
              "| Category | Count |",
              "|----------|-------|"]
    for cat, cnt in out_cats.most_common():
        lines.append(f"| {cat} | {cnt} |")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Classify BugsInPy bugs as in/out of scope for a3")
    p.add_argument("--projects", nargs="*", default=ALL_PROJECTS)
    p.add_argument("--out", type=Path, default=A3_ROOT / "results" / "bugsinpy_classified.md")
    p.add_argument("--json-out", type=Path, default=None)
    args = p.parse_args(argv)

    json_path = args.json_out or args.out.with_suffix(".json")

    results = classify_all(args.projects)
    write_report(results, args.out)
    json_path.write_text(
        json.dumps([asdict(r) for r in results], indent=2, default=str),
        encoding="utf-8",
    )

    in_scope = sum(1 for r in results if r.in_scope)
    print(f"Classified {len(results)} bugs:  {in_scope} in-scope,  {len(results)-in_scope} out-of-scope")
    print(f"Report → {args.out}")
    print(f"JSON   → {json_path}")

    # Print top categories
    cats = Counter(r.category for r in results if r.in_scope)
    for cat, cnt in cats.most_common(8):
        print(f"  {cat:25s}  {cnt:3d}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
