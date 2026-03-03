#!/usr/bin/env python3
"""
Step 2: Analyse the next N in-scope BugsInPy bugs, run a3-python on each,
and for every bug a3 gets wrong, build and execute a copilot-cli prompt
to improve a3-python.

Prerequisites:
  - Run classify_bugsinpy_scope.py first → results/bugsinpy_classified.json
  - copilot CLI available on PATH

Usage:
    python scripts/improve_a3_from_bugs.py                    # next 10 bugs
    python scripts/improve_a3_from_bugs.py --count 5          # next 5
    python scripts/improve_a3_from_bugs.py --dry-run          # don't invoke copilot
    python scripts/improve_a3_from_bugs.py --list             # show remaining queue
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Paths ───────────────────────────────────────────────────────────────────
A3_ROOT       = Path(__file__).resolve().parent.parent
BUGS_DIR      = A3_ROOT / "BugsInPy" / "projects"
CLASSIFIED    = A3_ROOT / "results" / "bugsinpy_classified.json"
STATE_FILE    = A3_ROOT / "results" / "improve_state.json"
LOG_FILE      = A3_ROOT / "results" / "improve_log.jsonl"
REPORT_FILE   = A3_ROOT / "results" / "improve_report.md"
COPILOT_CLI   = "copilot"
A3_TIMEOUT    = 90


# ═══════════════════════════════════════════════════════════════════════════
# State (tracks which bugs have been processed or resolved)
# ═══════════════════════════════════════════════════════════════════════════

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return {"resolved": [], "attempted": [], "skipped": []}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def bug_key(project: str, bug_id: int) -> str:
    return f"{project}#{bug_id}"


# ═══════════════════════════════════════════════════════════════════════════
# Load classified bugs
# ═══════════════════════════════════════════════════════════════════════════

def load_in_scope_bugs() -> List[dict]:
    """Load in-scope bugs from the classification JSON."""
    if not CLASSIFIED.exists():
        print(f"ERROR: {CLASSIFIED} not found.", file=sys.stderr)
        print("  Run first:  python scripts/classify_bugsinpy_scope.py", file=sys.stderr)
        sys.exit(1)
    all_bugs = json.loads(CLASSIFIED.read_text())
    return [b for b in all_bugs if b.get("in_scope")]


def get_queue(count: int) -> List[dict]:
    """Return next `count` in-scope bugs not yet resolved / attempted."""
    state = load_state()
    done = set(state.get("resolved", []) + state.get("attempted", []) + state.get("skipped", []))
    bugs = load_in_scope_bugs()
    queue = [b for b in bugs if bug_key(b["project"], b["bug_id"]) not in done]
    return queue[:count]


# ═══════════════════════════════════════════════════════════════════════════
# Patch extraction (reused from bugsinpy_eval.py)
# ═══════════════════════════════════════════════════════════════════════════

def _parse_patch(patch_text: str) -> Dict[str, Tuple[str, str]]:
    """Parse unified diff → {filename: (buggy_content, fixed_content)}."""
    files: Dict[str, Tuple[List[str], List[str]]] = {}
    current_file: Optional[str] = None
    buggy_lines: List[str] = []
    fixed_lines: List[str] = []

    for line in patch_text.splitlines(keepends=True):
        if line.startswith("diff --git"):
            if current_file is not None:
                files[current_file] = (buggy_lines, fixed_lines)
            parts = line.split()
            current_file = parts[3].lstrip("b/") if len(parts) >= 4 else None
            buggy_lines, fixed_lines = [], []
            continue
        if current_file is None:
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("@@"):
            buggy_lines.append("# @@ hunk @@\n")
            fixed_lines.append("# @@ hunk @@\n")
            continue
        if line.startswith("-"):
            buggy_lines.append(line[1:])
        elif line.startswith("+"):
            fixed_lines.append(line[1:])
        else:
            content = line[1:] if line.startswith(" ") else line
            buggy_lines.append(content)
            fixed_lines.append(content)

    if current_file is not None:
        files[current_file] = (buggy_lines, fixed_lines)

    result: Dict[str, Tuple[str, str]] = {}
    for fname, (blines, flines) in files.items():
        if fname.endswith(".py"):
            name_lower = Path(fname).name.lower()
            if not (name_lower.startswith("test_") or name_lower == "conftest.py"):
                result[fname] = ("".join(blines), "".join(flines))
    return result


# ═══════════════════════════════════════════════════════════════════════════
# a3 runner
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    file: str
    verdict: str   # SAFE | BUG | UNKNOWN | ERROR
    exit_code: int
    findings: List[dict] = field(default_factory=list)
    raw_output: str = ""
    duration: float = 0.0


def run_a3(filepath: Path) -> ScanResult:
    t0 = time.monotonic()
    cmd = [sys.executable, "-m", "a3_python", str(filepath),
           "--functions", "--deduplicate", "--min-confidence", "0.3"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=A3_TIMEOUT, cwd=str(A3_ROOT))
        raw = proc.stdout + proc.stderr
        ec = proc.returncode
    except subprocess.TimeoutExpired:
        return ScanResult(str(filepath), "ERROR", 3,
                          raw_output=f"timeout ({A3_TIMEOUT}s)",
                          duration=time.monotonic() - t0)
    except Exception as e:
        return ScanResult(str(filepath), "ERROR", 3,
                          raw_output=str(e),
                          duration=time.monotonic() - t0)

    verdict = {0: "SAFE", 1: "BUG", 2: "UNKNOWN"}.get(ec, "ERROR")
    findings = _parse_findings(raw)
    return ScanResult(str(filepath), verdict, ec, findings, raw[:3000],
                      time.monotonic() - t0)


def _parse_findings(output: str) -> List[dict]:
    findings = []
    pats = [
        re.compile(r"\[BUG\]\s+(?P<bt>[A-Z_]+)\s+\(line\s+(?P<ln>\d+)", re.I),
        re.compile(r"(?:bug|BUG)[:]\s*(?P<bt>[A-Z_]+).*?line\s+(?P<ln>\d+)", re.I),
        re.compile(r"Found bug[:]\s*(?P<bt>[A-Z_]+).*?on line\s+(?P<ln>\d+)", re.I),
    ]
    for line in output.splitlines():
        for pat in pats:
            m = pat.search(line)
            if m:
                findings.append({"bug_type": m.group("bt").upper(),
                                 "line": int(m.group("ln"))})
                break
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Evaluate one bug
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BugResult:
    project: str
    bug_id: int
    category: str
    a3_bug_type: str
    classification_reason: str
    # a3 results
    buggy_verdict: str = ""
    fixed_verdict: str = ""
    buggy_findings: List[dict] = field(default_factory=list)
    fixed_findings: List[dict] = field(default_factory=list)
    buggy_raw: str = ""
    fixed_raw: str = ""
    # Evaluation
    a3_correct: bool = False
    error_type: str = ""          # FALSE_NEGATIVE | FALSE_POSITIVE | BOTH_BUG | ""
    # Improvement
    prompt_generated: str = ""
    copilot_invoked: bool = False
    copilot_output: str = ""
    duration: float = 0.0


def evaluate_bug(bug: dict) -> BugResult:
    """Run a3 on buggy & fixed versions, classify result."""
    project, bug_id = bug["project"], bug["bug_id"]
    br = BugResult(
        project=project, bug_id=bug_id,
        category=bug.get("category", ""),
        a3_bug_type=bug.get("a3_bug_type", ""),
        classification_reason=bug.get("reason", ""),
    )

    patch_path = BUGS_DIR / project / "bugs" / str(bug_id) / "bug_patch.txt"
    if not patch_path.exists():
        br.error_type = "NO_PATCH"
        return br

    patch_text = patch_path.read_text(errors="replace")
    file_versions = _parse_patch(patch_text)
    if not file_versions:
        br.error_type = "NO_PATCH"
        return br

    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="a3_improve_") as tmpdir:
        tmp = Path(tmpdir)
        buggy_dir = tmp / "buggy"
        fixed_dir = tmp / "fixed"
        buggy_dir.mkdir()
        fixed_dir.mkdir()

        for fname, (bsrc, fsrc) in file_versions.items():
            for d, src in [(buggy_dir, bsrc), (fixed_dir, fsrc)]:
                p = d / fname
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(src, encoding="utf-8")

        for fname in file_versions:
            sr = run_a3(buggy_dir / fname)
            if sr.verdict == "BUG":
                br.buggy_verdict = "BUG"
            elif br.buggy_verdict != "BUG":
                br.buggy_verdict = sr.verdict
            br.buggy_findings.extend(sr.findings)
            br.buggy_raw += sr.raw_output[:1000] + "\n"

        for fname in file_versions:
            sr = run_a3(fixed_dir / fname)
            if sr.verdict == "BUG":
                br.fixed_verdict = "BUG"
            elif br.fixed_verdict != "BUG":
                br.fixed_verdict = sr.verdict
            br.fixed_findings.extend(sr.findings)
            br.fixed_raw += sr.raw_output[:1000] + "\n"

    br.duration = time.monotonic() - t0

    # Classify
    if br.buggy_verdict == "BUG" and br.fixed_verdict != "BUG":
        br.a3_correct = True
        br.error_type = ""
    elif br.buggy_verdict != "BUG" and br.fixed_verdict != "BUG":
        br.a3_correct = False
        br.error_type = "FALSE_NEGATIVE"
    elif br.buggy_verdict != "BUG" and br.fixed_verdict == "BUG":
        br.a3_correct = False
        br.error_type = "FALSE_POSITIVE"
    else:
        # Both BUG
        buggy_sigs = {(f["bug_type"], f["line"]) for f in br.buggy_findings}
        fixed_sigs = {(f["bug_type"], f["line"]) for f in br.fixed_findings}
        if buggy_sigs - fixed_sigs:
            br.a3_correct = True
            br.error_type = ""
        else:
            br.a3_correct = False
            br.error_type = "BOTH_BUG"

    return br


# ═══════════════════════════════════════════════════════════════════════════
# Improvement prompt generation
# ═══════════════════════════════════════════════════════════════════════════

def build_prompt(br: BugResult) -> str:
    """Build a copilot-cli prompt to improve a3-python for this bug."""
    patch_path = BUGS_DIR / br.project / "bugs" / str(br.bug_id) / "bug_patch.txt"
    patch = patch_path.read_text(errors="replace")[:4000] if patch_path.exists() else "(unavailable)"

    bug_info_path = BUGS_DIR / br.project / "bugs" / str(br.bug_id) / "bug.info"
    bug_info = ""
    if bug_info_path.exists():
        bug_info = bug_info_path.read_text(errors="replace")

    findings_str = json.dumps(br.buggy_findings[:10], indent=2) if br.buggy_findings else "(none)"
    fixed_findings_str = json.dumps(br.fixed_findings[:10], indent=2) if br.fixed_findings else "(none)"

    if br.error_type == "FALSE_NEGATIVE":
        return textwrap.dedent(f"""\
        I am improving a3-python, a Python static analysis tool in this workspace (a3_python/ directory).

        FALSE NEGATIVE: a3-python missed a known bug from the BugsInPy benchmark.

        Project     : {br.project}
        Bug ID      : {br.bug_id}
        Bug category: {br.category}
        Expected a3 bug type: {br.a3_bug_type}
        Classification reason: {br.classification_reason}

        Bug info:
        {bug_info}

        The buggy code should trigger a {br.a3_bug_type} finding, but a3 reported SAFE.

        Bug patch (the fix that was applied):
        ```
        {patch}
        ```

        a3 found these on the buggy code: {findings_str}
        a3 found these on the fixed code: {fixed_findings_str}

        a3 raw output on buggy code:
        {br.buggy_raw[:1500]}

        SPECIFIC TASK:
        1. Analyse the patch above. The *removed* lines (-) show the buggy code;
           the *added* lines (+) show the fix. Identify what class of bug this is
           (e.g., missing None check, missing type check, missing bounds guard,
           uncaught exception, etc.).

        2. Map this to a3's detection capabilities. The relevant a3 bug type is
           {br.a3_bug_type}. Look at:
           - a3_python/unsafe/  (bug type predicates — especially {br.a3_bug_type.lower()}.py)
           - a3_python/semantics/symbolic_vm.py  (how code is symbolically executed)
           - a3_python/analyzer.py  (the analysis pipeline)

        3. Implement a targeted improvement so a3 detects this class of bug.
           This could be:
           - Adding a new pattern to an existing unsafe checker
           - Improving the symbolic VM to track the relevant state
           - Adding a new heuristic in the interprocedural analysis
           - Improving taint/crash summary computation

        4. Verify the change doesn't break existing tests:
           python -m pytest tests/ -x -q

        Keep changes minimal and surgical. Do NOT refactor unrelated code.
        """)

    elif br.error_type == "FALSE_POSITIVE":
        return textwrap.dedent(f"""\
        I am improving a3-python, a Python static analysis tool in this workspace (a3_python/ directory).

        FALSE POSITIVE: a3-python incorrectly flags the *fixed* (correct) code as buggy.

        Project     : {br.project}
        Bug ID      : {br.bug_id}

        a3 findings on the FIXED (correct) code: {fixed_findings_str}

        Bug patch (context):
        ```
        {patch}
        ```

        SPECIFIC TASK:
        1. Identify which a3 checker produced the false positive finding(s).
        2. Determine why it fails to recognise the safe pattern in the fixed code.
        3. Add a precision improvement (guard, filter, or pattern exclusion) so
           the false positive no longer fires. Do NOT suppress real bugs.
        4. Verify: python -m pytest tests/ -x -q
        5.  **Make sure** you're using deep kitchensink/symbolic analysis/barrier analysis/dse and not just pattern matching
        """)

    elif br.error_type == "BOTH_BUG":
        return textwrap.dedent(f"""\
        I am improving a3-python, a Python static analysis tool in this workspace (a3_python/ directory).

        SAME-FINDINGS: a3-python reports identical findings on both the buggy and
        fixed versions — it does not see that the fix resolved the issue.

        Project     : {br.project}
        Bug ID      : {br.bug_id}

        Buggy-code findings: {findings_str}
        Fixed-code findings: {fixed_findings_str}

        Bug patch:
        ```
        {patch}
        ```

        SPECIFIC TASK:
        1. Determine if the findings are related to the actual bug or are
           pre-existing unrelated issues.
        2. If related: improve a3's flow-sensitivity so findings resolve post-fix.
        3. If unrelated: also add detection for the actual bug shown in the patch.
        4. Verify: python -m pytest tests/ -x -q
        5.  **Make sure** you're using deep kitchensink/symbolic analysis/barrier analysis/dse and not just pattern matching
        """)
    else:
        return ""


# ═══════════════════════════════════════════════════════════════════════════
# Copilot CLI invocation
# ═══════════════════════════════════════════════════════════════════════════

def invoke_copilot(prompt: str) -> str:
    """Call copilot CLI with the given prompt. Returns raw output."""
    # Write prompt to a temp file to avoid shell escaping issues
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False,
                                     prefix="a3_prompt_") as f:
        f.write(prompt)
        prompt_file = f.name

    try:
        cmd = [
            COPILOT_CLI,
            "-p", f"$(cat {prompt_file})",
            "--autopilot",
            "--allow-all-tools",
        ]

        # Use shell=True so the $(cat ...) subshell works
        shell_cmd = f'{COPILOT_CLI} -p "$(cat {prompt_file})" --autopilot --allow-all-tools'
        print(f"    → Invoking copilot-cli …", file=sys.stderr)
        os.system(shell_cmd)
        return "COPILOT_INVOKED"
    except subprocess.TimeoutExpired:
        return "COPILOT_TIMEOUT"
    except Exception as e:
        return f"COPILOT_ERROR: {e}"
    finally:
        try:
            os.unlink(prompt_file)
        except OSError:
            pass
        


# ═══════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════

def log_result(br: BugResult) -> None:
    """Append one result to the JSONL log."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "project": br.project,
        "bug_id": br.bug_id,
        "category": br.category,
        "a3_bug_type": br.a3_bug_type,
        "buggy_verdict": br.buggy_verdict,
        "fixed_verdict": br.fixed_verdict,
        "a3_correct": br.a3_correct,
        "error_type": br.error_type,
        "copilot_invoked": br.copilot_invoked,
        "duration": round(br.duration, 1),
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ═══════════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════════

def write_report(results: List[BugResult], state: dict) -> None:
    """Write / overwrite a cumulative Markdown report."""
    lines = [
        "# a3-python Improvement Report (BugsInPy In-Scope Bugs)",
        f"_Updated: {datetime.now().isoformat(timespec='seconds')}_\n",
    ]

    # Load all in-scope to get totals
    all_in_scope = load_in_scope_bugs()
    total_in_scope = len(all_in_scope)
    resolved = len(state.get("resolved", []))
    attempted = len(state.get("attempted", []))

    lines += [
        "## Progress\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total in-scope bugs | {total_in_scope} |",
        f"| Resolved (a3 correct) | {resolved} |",
        f"| Attempted (prompt sent) | {attempted} |",
        f"| Remaining | {total_in_scope - resolved - attempted} |",
        "",
    ]

    if results:
        lines += [
            "## This Run\n",
            "| # | Project | Bug | Category | a3 Type | Buggy | Fixed | Result | Copilot |",
            "|---|---------|-----|----------|---------|-------|-------|--------|---------|",
        ]
        for i, br in enumerate(results, 1):
            cop = "✅" if br.copilot_invoked else "—"
            correct = "✅" if br.a3_correct else f"❌ {br.error_type}"
            lines.append(
                f"| {i} | {br.project} | {br.bug_id} | {br.category} "
                f"| {br.a3_bug_type} | {br.buggy_verdict} | {br.fixed_verdict} "
                f"| {correct} | {cop} |"
            )

    # Include prompts for incorrect bugs
    incorrect = [br for br in results if not br.a3_correct and br.prompt_generated]
    if incorrect:
        lines += ["", "## Generated Improvement Prompts\n"]
        for br in incorrect:
            lines += [
                f"### {br.project} bug #{br.bug_id} — {br.error_type} ({br.category})\n",
                "<details><summary>Prompt (click to expand)</summary>\n",
                "```",
                br.prompt_generated,
                "```",
                "</details>\n",
            ]
            if br.copilot_output:
                lines += [
                    "<details><summary>Copilot output</summary>\n",
                    "```",
                    br.copilot_output[:3000],
                    "```",
                    "</details>\n",
                ]

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# Main loop
# ═══════════════════════════════════════════════════════════════════════════

def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="improve_a3_from_bugs",
        description="Analyse in-scope BugsInPy bugs and improve a3-python via copilot-cli",
    )
    p.add_argument("--count", type=int, default=10,
                   help="Number of bugs to process (default: 10)")
    p.add_argument("--dry-run", action="store_true",
                   help="Generate prompts but don't invoke copilot")
    p.add_argument("--list", action="store_true",
                   help="Just show the queue and exit")
    p.add_argument("--reset", action="store_true",
                   help="Clear state (re-process all bugs)")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args(argv)

    if args.reset:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
        print("State cleared.")
        return 0

    state = load_state()

    if args.list:
        queue = get_queue(9999)
        print(f"Remaining in-scope bugs: {len(queue)}")
        print(f"Already resolved: {len(state.get('resolved', []))}")
        print(f"Already attempted: {len(state.get('attempted', []))}")
        print()
        for i, b in enumerate(queue[:30], 1):
            print(f"  {i:3d}. {b['project']:15s} #{b['bug_id']:3d}  "
                  f"{b['category']:20s}  {b['a3_bug_type']}")
        if len(queue) > 30:
            print(f"  ... and {len(queue)-30} more")
        return 0

    queue = get_queue(args.count)
    if not queue:
        print("All in-scope bugs have been processed!")
        return 0

    print(f"Processing {len(queue)} in-scope bugs …")
    print(f"  Resolved so far: {len(state.get('resolved', []))}")
    print(f"  Attempted so far: {len(state.get('attempted', []))}")
    print()

    results: List[BugResult] = []
    for i, bug in enumerate(queue, 1):
        bk = bug_key(bug["project"], bug["bug_id"])
        print(f"[{i}/{len(queue)}] {bug['project']} bug#{bug['bug_id']}  "
              f"({bug['category']} → {bug['a3_bug_type']})")

        # 1. Evaluate
        br = evaluate_bug(bug)
        log_result(br)

        if br.a3_correct:
            print(f"  ✓ a3 is already correct! (buggy={br.buggy_verdict}, "
                  f"fixed={br.fixed_verdict})")
            state.setdefault("resolved", []).append(bk)
            save_state(state)
            results.append(br)
            continue

        print(f"  ✗ {br.error_type}  (buggy={br.buggy_verdict}, "
              f"fixed={br.fixed_verdict})")

        # 2. Generate prompt
        prompt = build_prompt(br)
        br.prompt_generated = prompt

        if not prompt:
            print(f"  → No prompt generated (error_type={br.error_type})")
            state.setdefault("skipped", []).append(bk)
            save_state(state)
            results.append(br)
            continue

        # 3. Save prompt to file
        prompt_dir = A3_ROOT / "results" / "prompts"
        prompt_dir.mkdir(parents=True, exist_ok=True)
        prompt_file = prompt_dir / f"{bug['project']}_bug{bug['bug_id']}.txt"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  → Prompt saved: {prompt_file.relative_to(A3_ROOT)}")
        output = ""
        # 4. Invoke copilot (unless --dry-run)
        if not args.dry_run:
            output = invoke_copilot(prompt)
            br.copilot_invoked = True
            br.copilot_output = output[:5000]
            print(f"  → Copilot returned ({len(output)} chars)")

            # 5. Re-evaluate to check if fixed
            print(f"  → Re-evaluating …")
            br2 = evaluate_bug(bug)
            if br2.a3_correct:
                print(f"  ✓ FIX VERIFIED! a3 now gets it right.")
                state.setdefault("resolved", []).append(bk)
            else:
                print(f"  ✗ Still incorrect ({br2.error_type}). "
                      f"Prompt saved for manual review.")
                state.setdefault("attempted", []).append(bk)
        else:
            print(f"  → [dry-run] Skipping copilot invocation")
            state.setdefault("attempted", []).append(bk)

        save_state(state)
        results.append(br)

    # Summary
    correct = sum(1 for r in results if r.a3_correct)
    incorrect = sum(1 for r in results if not r.a3_correct)
    print(f"\n{'='*60}")
    print(f"  Processed: {len(results)}  |  Already correct: {correct}  "
          f"|  Needs improvement: {incorrect}")
    print(f"  Total resolved: {len(state.get('resolved', []))}")
    print(f"  Total attempted: {len(state.get('attempted', []))}")
    print(f"{'='*60}")

    write_report(results, state)
    print(f"\nReport → {REPORT_FILE}")
    print(f"Log    → {LOG_FILE}")
    print(f"Prompts → results/prompts/")

    return 0


if __name__ == "__main__":
    sys.exit(main())
