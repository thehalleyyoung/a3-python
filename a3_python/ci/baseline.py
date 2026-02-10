"""
Baseline ratchet for incremental adoption.

Maintains a ``.a3-baseline.json`` file that records all *accepted*
findings.  On each CI run the current SARIF is diffed against the baseline:

- New findings not in the baseline → CI fails (author must fix or accept).
- Findings that disappeared → automatically pruned from baseline.
- ``a3 baseline accept`` → adds current findings to baseline.

This lets large codebases adopt a3 without blocking on
pre-existing issues.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


# ── Fingerprinting ───────────────────────────────────────────────────────────

def _fingerprint(result: dict[str, Any]) -> str:
    """
    Compute a stable identity string for a SARIF result.

    We use (ruleId, qualifiedName, artifactUri) so that a finding is
    considered "the same" even if the exact line number shifts.
    """
    rule_id = result.get("ruleId", "unknown")
    qualified = result.get("properties", {}).get("qualifiedName", "")
    uri = ""
    locs = result.get("locations", [])
    if locs:
        phys = locs[0].get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "")
    return f"{rule_id}::{qualified}::{uri}"


# ── Baseline I/O ─────────────────────────────────────────────────────────────

_DEFAULT_PATH = ".a3-baseline.json"


def _baseline_path(repo_root: Path, explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    return repo_root / _DEFAULT_PATH


def load_baseline(repo_root: Path, path: str | None = None) -> dict[str, Any]:
    """Load the baseline file, returning an empty baseline if missing."""
    bp = _baseline_path(repo_root, path)
    if bp.exists():
        with open(bp) as f:
            return json.load(f)
    return {"version": 1, "findings": {}}


def save_baseline(
    baseline: dict[str, Any],
    repo_root: Path,
    path: str | None = None,
) -> Path:
    """Write the baseline file and return its path."""
    bp = _baseline_path(repo_root, path)
    bp.parent.mkdir(parents=True, exist_ok=True)
    with open(bp, "w") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)
    return bp


# ── Diff logic ───────────────────────────────────────────────────────────────

def diff_sarif_against_baseline(
    sarif: dict[str, Any],
    baseline: dict[str, Any],
) -> tuple[list[dict], list[str]]:
    """
    Compare current SARIF results against the baseline.

    Returns
    -------
    new_findings : list[dict]
        SARIF result objects present in the scan but **not** in the baseline.
    fixed_fingerprints : list[str]
        Fingerprints that were in the baseline but are no longer reported
        (the code has been fixed).
    """
    known = set(baseline.get("findings", {}).keys())

    current_results = []
    for run in sarif.get("runs", []):
        current_results.extend(run.get("results", []))

    current_fps: dict[str, dict] = {}
    for r in current_results:
        fp = _fingerprint(r)
        current_fps[fp] = r

    new_findings = [r for fp, r in current_fps.items() if fp not in known]
    fixed = [fp for fp in known if fp not in current_fps]

    return new_findings, fixed


# ── Accept / update ──────────────────────────────────────────────────────────

def accept_sarif_into_baseline(
    sarif: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    """
    Merge all current SARIF results into the baseline.

    Existing entries are kept; new ones are added; findings no longer
    present are pruned (the ratchet only goes forward).
    """
    current_results = []
    for run in sarif.get("runs", []):
        current_results.extend(run.get("results", []))

    new_findings: dict[str, dict[str, Any]] = {}
    for r in current_results:
        fp = _fingerprint(r)
        new_findings[fp] = {
            "ruleId": r.get("ruleId"),
            "qualifiedName": r.get("properties", {}).get("qualifiedName", ""),
            "message": r.get("message", {}).get("text", ""),
        }

    baseline["findings"] = new_findings
    return baseline


# ── CLI sub-command entry points ─────────────────────────────────────────────

def cmd_baseline_diff(
    sarif_path: str,
    repo_root: Path,
    baseline_path: str | None = None,
    *,
    auto_issue: bool = False,
) -> int:
    """
    ``a3 baseline diff`` entry point.

    Returns 0 if no new findings, 1 if there are new findings.
    """
    from .sarif import load_sarif

    sarif = load_sarif(sarif_path)
    baseline = load_baseline(repo_root, baseline_path)
    new_findings, fixed = diff_sarif_against_baseline(sarif, baseline)

    if fixed:
        print(f"✅  {len(fixed)} finding(s) fixed since last baseline")
        # Auto-prune fixed findings
        for fp in fixed:
            baseline.get("findings", {}).pop(fp, None)
        save_baseline(baseline, repo_root, baseline_path)

    if not new_findings:
        print("✅  No new findings — baseline check passed")
        return 0

    print(f"❌  {len(new_findings)} NEW finding(s) not in baseline:\n")
    for r in new_findings:
        rule = r.get("ruleId", "?")
        msg = r.get("message", {}).get("text", "")
        loc = ""
        if r.get("locations"):
            phys = r["locations"][0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", "?")
            loc = f"  {uri}:{line}"
        print(f"  [{rule}]{loc}  {msg}")

    if auto_issue:
        _auto_create_issues(new_findings, repo_root)

    print(
        "\nTo accept these into the baseline, run:\n"
        f"  a3 baseline accept --sarif {sarif_path}"
    )
    return 1


def cmd_baseline_accept(
    sarif_path: str,
    repo_root: Path,
    baseline_path: str | None = None,
) -> int:
    """``a3 baseline accept`` entry point."""
    from .sarif import load_sarif

    sarif = load_sarif(sarif_path)
    baseline = load_baseline(repo_root, baseline_path)
    updated = accept_sarif_into_baseline(sarif, baseline)
    out = save_baseline(updated, repo_root, baseline_path)
    n = len(updated.get("findings", {}))
    print(f"✅  Baseline updated: {n} finding(s) recorded in {out}")
    return 0


# ── Auto-issue filing ────────────────────────────────────────────────────────

def _auto_create_issues(
    new_findings: list[dict[str, Any]],
    repo_root: Path,
) -> None:
    """Create GitHub issues for new findings via ``gh`` CLI."""
    import subprocess
    import shutil

    gh = shutil.which("gh")
    if not gh:
        print("  ⚠  `gh` CLI not found — skipping auto-issue creation")
        return

    for r in new_findings:
        rule = r.get("ruleId", "PFS999")
        msg = r.get("message", {}).get("text", "")
        qname = r.get("properties", {}).get("qualifiedName", "unknown")
        title = f"[a3] {rule}: {msg}"

        body = (
            f"## Automated finding from a3\n\n"
            f"**Rule:** {rule}\n"
            f"**Function:** `{qname}`\n"
            f"**Details:** {msg}\n\n"
            f"This issue was automatically filed by `a3 baseline diff --auto-issue`.\n"
        )

        try:
            subprocess.run(
                [gh, "issue", "create", "--title", title, "--body", body],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
            )
            print(f"  📝 Created issue: {title[:80]}")
        except subprocess.CalledProcessError as e:
            print(f"  ⚠  Failed to create issue for {qname}: {e.stderr.strip()}")
