#!/usr/bin/env python3
"""
Bugfix-Driven Improvement Pipeline for qsat.

Iterative loop that:
  1. SCAN  — Discovers repos, finds bugfix commits, runs qsat on pre/post MIR
  2. DIAGNOSE — Identifies MISSED/PARTIAL bugs, maps to pathological detector gaps
  3. IMPROVE — Feeds targeted improvement prompt to copilot CLI, rebuilds qsat
  4. LOOP  — Re-scans to measure improvement; stops on plateau or max iterations

Usage:
    python3 scan_bugfix_history.py                          # Full pipeline (default 5 iters)
    python3 scan_bugfix_history.py --max-iterations 10      # More iterations
    python3 scan_bugfix_history.py --scan-only              # Phase 1 only (no improvements)
    python3 scan_bugfix_history.py --repo test_repos/tokio   # Specific repo
    python3 scan_bugfix_history.py --repo-url https://github.com/tokio-rs/tokio
    python3 scan_bugfix_history.py --max-commits 50
    python3 scan_bugfix_history.py --dry-run                 # Print prompts, don't execute
    python3 scan_bugfix_history.py --resume                  # Resume from last checkpoint
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── paths ──────────────────────────────────────────────────────────────────────
WORKSPACE = Path(__file__).parent.absolute()
BUILD_DIR = WORKSPACE / "build"
QSAT_BINARY = BUILD_DIR / "bin" / "qsat"
RESULTS_DIR = WORKSPACE / "results" / "bugfix_scan"
STATE_FILE = RESULTS_DIR / "pipeline_state.json"
TEST_REPOS = WORKSPACE / "test_repos"

ALL_BUG_TYPES = [
    "overflow", "uaf", "double_free", "leak", "uninit", "null_ptr", "bounds",
    "race", "deadlock", "send_sync",
    "panic", "nontermination", "stack_overflow", "assert_fail",
    "div_zero", "fp_domain",
    "type_confusion", "info_leak", "timing_channel", "iterator_invalid",
]

BUGFIX_GREP_TERMS = [
    "fix", "bug", "crash", "panic", "overflow", "leak", "race", "deadlock",
    "use-after", "double.free", "null", "UB", "unsound", "CVE", "RUSTSEC",
    "security", "vulnerability", "safety", "unsafe", "memory",
]

# Maps commit keywords → qsat bug types for classification
BUG_KEYWORD_MAP = {
    "overflow": "overflow", "underflow": "overflow",
    "panic": "panic", "unwrap": "panic", "expect": "panic",
    "uaf": "uaf", "use-after-free": "uaf", "use after free": "uaf",
    "double free": "double_free", "double-free": "double_free",
    "leak": "leak", "memory leak": "leak",
    "null": "null_ptr", "nullptr": "null_ptr", "null pointer": "null_ptr",
    "race": "race", "data race": "race", "concurrent": "race",
    "deadlock": "deadlock",
    "bounds": "bounds", "out-of-bounds": "bounds", "index": "bounds",
    "uninit": "uninit", "uninitialized": "uninit",
    "div": "div_zero", "divide by zero": "div_zero",
}

# Maps qsat bug types → detector source files
DETECTOR_FILE_MAP = {
    "uaf": "src/detector_uaf.cpp",
    "null_ptr": "src/detector_null_ptr.cpp",
    "panic": "src/detector_panic.cpp",
    "race": "src/detector_race.cpp",
    "overflow": "src/bug_detector_overflow.cpp",
    "double_free": "src/detector_double_free.cpp",
    "leak": "src/detector_leak.cpp",
    "uninit": "src/detector_uninit.cpp",
    "bounds": "src/bug_detector_bounds.cpp",
    "deadlock": "src/detector_deadlock.cpp",
    "div_zero": "src/detector_div_zero.cpp",
    "send_sync": "src/detector_send_sync.cpp",
    "stack_overflow": "src/detector_stack.cpp",
    "assert_fail": "src/detector_assert_fail.cpp",
    "nontermination": "src/detector_nontermination.cpp",
    "type_confusion": "src/detector_type_confusion.cpp",
    "info_leak": "src/detector_info_flow.cpp",
    "iterator_invalid": "src/detector_iterator.cpp",
    "fp_domain": "src/detector_fp_domain.cpp",
    "timing_channel": "src/detector_info_flow.cpp",
}

PLATEAU_THRESHOLD = 0.02   # Stop if detection rate improves < 2%
PLATEAU_PATIENCE = 2       # Need 2 consecutive plateau iterations to stop
DEFAULT_MAX_ITERS = 5
COPILOT_TIMEOUT = 900      # 15 min for improvement phase


# ── logging ────────────────────────────────────────────────────────────────────
def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")


def log_phase(phase: str, iteration: int):
    print(f"\n{'='*70}")
    print(f"  ITERATION {iteration} — PHASE: {phase}")
    print(f"{'='*70}\n")


# ── repo discovery ─────────────────────────────────────────────────────────────
def discover_repos(specific_repo: str = "") -> List[Path]:
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
                subprocess.run(
                    ["git", "clone", "--depth", "200", specific_repo, str(dest)],
                    capture_output=True, timeout=120,
                )
            if dest.exists():
                repos.append(dest)
        return repos

    # Scan everything in test_repos/
    if TEST_REPOS.exists():
        for child in sorted(TEST_REPOS.iterdir()):
            if child.is_dir() and (child / ".git").exists():
                repos.append(child)

    # Try discovering new repos via gh CLI
    try:
        queries = [
            "gh search repos --language=Rust org:Azure --limit 5 --json fullName --jq '.[].fullName'",
            "gh search repos --language=Rust org:tokio-rs --limit 5 --json fullName --jq '.[].fullName'",
            "gh search repos --language=Rust org:hyperium --limit 5 --json fullName --jq '.[].fullName'",
        ]
        for q in queries:
            result = subprocess.run(
                q, shell=True, capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.strip().splitlines():
                name = line.strip().split("/")[-1]
                dest = TEST_REPOS / name
                if not dest.exists() and name:
                    log(f"Discovered {line} — cloning")
                    subprocess.run(
                        ["git", "clone", "--depth", "200",
                         f"https://github.com/{line.strip()}.git", str(dest)],
                        capture_output=True, timeout=120,
                    )
                    if dest.exists():
                        repos.append(dest)
    except Exception as e:
        log(f"Repo discovery failed (non-fatal): {e}", "WARN")

    return repos


def deepen_repo(repo: Path, depth: int = 500):
    """Ensure repo has enough history for bugfix scanning."""
    try:
        subprocess.run(
            ["git", "fetch", "--deepen", str(depth)],
            cwd=str(repo), capture_output=True, timeout=60,
        )
    except Exception:
        pass  # shallow clone is fine, just less history


# ── bugfix commit extraction ───────────────────────────────────────────────────
def find_bugfix_commits(repo: Path, max_commits: int = 50) -> List[Dict]:
    """Search git history for bug-fix commits."""
    grep_args = []
    for term in BUGFIX_GREP_TERMS:
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
        sha = parts[0]
        msg = parts[1] if len(parts) > 1 else ""

        # Only keep commits that touch .rs files
        try:
            diff_result = subprocess.run(
                ["git", "--no-pager", "diff", "--name-only", f"{sha}~1", sha, "--", "*.rs"],
                cwd=str(repo), capture_output=True, text=True, timeout=10,
            )
            rs_files = [f for f in diff_result.stdout.strip().splitlines() if f.endswith(".rs")]
            if not rs_files:
                continue
        except Exception:
            continue

        # Infer bug type from commit message
        bug_type = infer_bug_type(msg)

        commits.append({
            "sha": sha,
            "message": msg,
            "rs_files": rs_files,
            "bug_type": bug_type,
        })
        if len(commits) >= max_commits:
            break

    return commits


def infer_bug_type(message: str) -> str:
    """Infer qsat bug type from commit message text using word boundaries."""
    msg_lower = message.lower()
    for keyword, bug_type in BUG_KEYWORD_MAP.items():
        # Use regex to avoid partial matches (e.g. "expect" inside "unexpected")
        # \b matches word boundary. 
        # Note: some keywords might have non-word chars like "double-free" or "out-of-bounds"
        # We need to be careful.
        
        # If keyword has special chars, just use substring search but check boundaries manually?
        # Actually re.escape + \b is usually fine except for symbols.
        # "double-free" -> \bdouble\-free\b. "-" is not a word char, so "double" is a word, "free" is a word.
        # So "double-free" matches "double-free".
        
        try:
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, msg_lower):
                return bug_type
        except re.error:
            # Fallback to simple substring if regex fails (unlikely)
            if keyword in msg_lower:
                return bug_type
                
    return "unknown"


# ── MIR extraction & qsat evaluation ──────────────────────────────────────────
def extract_file_at_commit(repo: Path, sha: str, filepath: str) -> Optional[str]:
    """Extract file content at a specific commit."""
    try:
        result = subprocess.run(
            ["git", "--no-pager", "show", f"{sha}:{filepath}"],
            cwd=str(repo), capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except Exception:
        return None


def compile_to_mir(rust_source: str) -> Optional[str]:
    """Compile Rust source to MIR. Returns MIR text or None."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False) as f:
        f.write(rust_source)
        rs_file = f.name
    try:
        result = subprocess.run(
            ["rustc", "--edition", "2021", "-Z", "unpretty=mir",
             "-C", "overflow-checks=off", "-A", "warnings", rs_file],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "RUSTC_BOOTSTRAP": "1"},
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        return None
    except Exception:
        return None
    finally:
        os.unlink(rs_file)


def run_qsat(mir_text: str, timeout: int = 30) -> Dict:
    """Run qsat on MIR text. Returns {result, details}."""
    if not QSAT_BINARY.exists():
        build_qsat()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".mir", delete=False) as f:
        f.write(mir_text)
        mir_file = f.name
    try:
        result = subprocess.run(
            [str(QSAT_BINARY), "--bug-types", ",".join(ALL_BUG_TYPES),
             "--timeout", str(timeout), mir_file],
            capture_output=True, text=True, timeout=timeout + 10,
        )
        output = result.stdout + result.stderr
        if "BUG FOUND" in output or "Bug type:" in output:
            return {"result": "BUG", "details": output[:1000]}
        if "SAFE" in output or "Program verified" in output:
            return {"result": "SAFE", "details": output[:500]}
        return {"result": "UNKNOWN", "details": output[:500]}
    except subprocess.TimeoutExpired:
        return {"result": "UNKNOWN", "details": "timeout"}
    except Exception as e:
        return {"result": "UNKNOWN", "details": str(e)}
    finally:
        os.unlink(mir_file)


def build_qsat():
    """Build qsat from source."""
    log("Building qsat...")
    BUILD_DIR.mkdir(exist_ok=True)
    subprocess.run(
        ["cmake", "..", "-DCMAKE_BUILD_TYPE=Release", "-DENABLE_Z3=ON",
         "-DENABLE_SCS=OFF", "-DENABLE_MOSEK=OFF", "-DENABLE_SPARSE_SOS=ON"],
        cwd=str(BUILD_DIR), capture_output=True, timeout=60,
    )
    ncpu = os.cpu_count() or 4
    result = subprocess.run(
        ["make", f"-j{ncpu}"],
        cwd=str(BUILD_DIR), capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        log(f"Build failed: {result.stderr[-500:]}", "ERROR")
        raise RuntimeError("qsat build failed")
    log("qsat built successfully")


# ── classification ─────────────────────────────────────────────────────────────
def classify(pre_result: str, post_result: str) -> str:
    """Classify a (pre-fix, post-fix) qsat result pair."""
    if pre_result == "BUG" and post_result == "SAFE":
        return "DETECTED"
    if pre_result == "BUG" and post_result == "BUG":
        return "PARTIAL"
    if pre_result == "SAFE" and post_result == "SAFE":
        return "MISSED"
    if pre_result == "SAFE" and post_result == "BUG":
        return "INVERTED"
    return "INCONCLUSIVE"


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: SCAN — find bugfix commits, run qsat, classify
# ══════════════════════════════════════════════════════════════════════════════
def phase_scan(repos: List[Path], max_commits: int = 50) -> List[Dict]:
    """Scan repos for bugfix commits, evaluate qsat on each."""
    all_results = []

    for repo in repos:
        repo_name = repo.name
        log(f"Scanning {repo_name}...")
        deepen_repo(repo)
        commits = find_bugfix_commits(repo, max_commits=max_commits)
        log(f"  Found {len(commits)} bugfix commits in {repo_name}")

        for commit in commits:
            for rs_file in commit["rs_files"][:3]:  # limit files per commit
                # Extract pre-fix and post-fix source
                pre_src = extract_file_at_commit(repo, f"{commit['sha']}~1", rs_file)
                post_src = extract_file_at_commit(repo, commit["sha"], rs_file)
                if not pre_src or not post_src:
                    continue

                # Compile to MIR
                pre_mir = compile_to_mir(pre_src)
                post_mir = compile_to_mir(post_src)
                if not pre_mir and not post_mir:
                    continue  # skip if neither compiles (dependency issues)

                # Run qsat
                pre_qsat = run_qsat(pre_mir) if pre_mir else {"result": "UNKNOWN", "details": "no MIR"}
                post_qsat = run_qsat(post_mir) if post_mir else {"result": "UNKNOWN", "details": "no MIR"}

                classification = classify(pre_qsat["result"], post_qsat["result"])
                should_detect = commit["bug_type"] != "unknown"

                entry = {
                    "repo": repo_name,
                    "commit": commit["sha"],
                    "message": commit["message"],
                    "file": rs_file,
                    "bug_type_from_commit": commit["bug_type"],
                    "pre_fix_qsat": pre_qsat["result"],
                    "post_fix_qsat": post_qsat["result"],
                    "pre_fix_details": pre_qsat["details"][:300],
                    "post_fix_details": post_qsat["details"][:300],
                    "classification": classification,
                    "should_detect": should_detect,
                }
                all_results.append(entry)

                # Log with context about detectability
                status_suffix = ""
                if not should_detect:
                    status_suffix = " (ignored: unknown bug type)"
                
                log(f"  {commit['sha'][:7]} {rs_file}: {classification}{status_suffix} "
                    f"(pre={pre_qsat['result']}, post={post_qsat['result']})")

    return all_results


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2: DIAGNOSE — analyze gaps, identify pathological patterns
# ══════════════════════════════════════════════════════════════════════════════
def phase_diagnose(results: List[Dict]) -> Dict:
    """Analyze scan results to find pathological gaps in qsat."""
    total = len(results)
    by_class = defaultdict(list)
    by_bug_type = defaultdict(list)
    detector_gaps = defaultdict(list)

    for r in results:
        by_class[r["classification"]].append(r)
        if r["bug_type_from_commit"] != "unknown":
            by_bug_type[r["bug_type_from_commit"]].append(r)

    # Compute detection rate (only for entries where should_detect=True)
    detectable = [r for r in results if r.get("should_detect")]
    detected = [r for r in detectable if r["classification"] == "DETECTED"]
    partial = [r for r in detectable if r["classification"] == "PARTIAL"]
    missed = [r for r in detectable if r["classification"] == "MISSED"]
    inverted = [r for r in detectable if r["classification"] == "INVERTED"]

    detection_rate = len(detected) / max(len(detectable), 1)
    partial_rate = len(partial) / max(len(detectable), 1)

    # Group MISSED + PARTIAL by bug type → detector gaps
    for r in missed + partial:
        bug_type = r["bug_type_from_commit"]
        detector_file = DETECTOR_FILE_MAP.get(bug_type, "unknown")
        detector_gaps[detector_file].append(r)

    # Build diagnosis report
    diagnosis = {
        "total_analyzed": total,
        "detectable": len(detectable),
        "detected": len(detected),
        "partial": len(partial),
        "missed": len(missed),
        "inverted": len(inverted),
        "inconclusive": len(by_class.get("INCONCLUSIVE", [])),
        "detection_rate": detection_rate,
        "partial_rate": partial_rate,
        "detector_gaps": {
            det: [{"repo": r["repo"], "commit": r["commit"],
                   "message": r["message"], "file": r["file"],
                   "classification": r["classification"],
                   "bug_type": r["bug_type_from_commit"],
                   "pre_fix_details": r.get("pre_fix_details", "")}
                  for r in entries]
            for det, entries in detector_gaps.items()
        },
        "pathological_patterns": _identify_pathological_patterns(missed, partial),
    }

    log(f"Diagnosis: {len(detected)} DETECTED, {len(partial)} PARTIAL, "
        f"{len(missed)} MISSED, {len(inverted)} INVERTED out of {len(detectable)} detectable")
    log(f"Detection rate: {detection_rate:.1%}, Partial rate: {partial_rate:.1%}")

    return diagnosis


def _identify_pathological_patterns(missed: List[Dict], partial: List[Dict]) -> List[Dict]:
    """Identify recurring weakness patterns across missed/partial bugs."""
    patterns = []
    type_counts = defaultdict(int)

    for r in missed + partial:
        type_counts[r["bug_type_from_commit"]] += 1

    for bug_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        examples = [r for r in missed + partial if r["bug_type_from_commit"] == bug_type]
        detector = DETECTOR_FILE_MAP.get(bug_type, "unknown")
        patterns.append({
            "bug_type": bug_type,
            "count": count,
            "detector_file": detector,
            "severity": "HIGH" if count >= 3 else "MEDIUM" if count >= 2 else "LOW",
            "examples": [{"repo": e["repo"], "commit": e["commit"][:7],
                          "message": e["message"][:80]} for e in examples[:5]],
        })

    return patterns


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3: IMPROVE — generate + apply targeted fixes via copilot CLI
# ══════════════════════════════════════════════════════════════════════════════
def phase_improve(diagnosis: Dict, iteration: int, dry_run: bool = False,
                  model: str = "claude-sonnet-4") -> bool:
    """Generate and apply improvements for the worst detector gaps."""
    gaps = diagnosis.get("detector_gaps", {})
    patterns = diagnosis.get("pathological_patterns", [])

    if not gaps and not patterns:
        log("No gaps to fix — all bugs detected!")
        return False

    prompt = _build_improvement_prompt(diagnosis, iteration)

    # Save prompt for reference
    prompt_file = RESULTS_DIR / f"improvement_prompt_iter{iteration}.md"
    prompt_file.write_text(prompt)
    log(f"Improvement prompt saved to {prompt_file}")

    if dry_run:
        log("DRY RUN — skipping copilot execution")
        return False

    # Run copilot CLI to apply improvements
    log("Running copilot CLI for improvements...")
    success = _run_copilot(prompt, model=model)

    if success:
        # Rebuild qsat
        try:
            build_qsat()
            log("Rebuild successful after improvements")
            return True
        except RuntimeError:
            log("Rebuild failed after improvements — reverting", "ERROR")
            return False
    else:
        log("Copilot improvement phase failed", "WARN")
        return False


def _build_improvement_prompt(diagnosis: Dict, iteration: int) -> str:
    """Build a targeted improvement prompt from diagnosis."""
    patterns = diagnosis.get("pathological_patterns", [])
    gaps = diagnosis.get("detector_gaps", {})

    # Build per-detector improvement sections
    detector_sections = []
    for pattern in patterns:
        if pattern["severity"] == "LOW":
            continue

        det_file = pattern["detector_file"]
        bug_type = pattern["bug_type"]
        examples = pattern["examples"]
        example_text = "\n".join(
            f"  - {e['repo']} ({e['commit']}): {e['message']}" for e in examples
        )

        # Get the actual gap entries with details
        gap_entries = gaps.get(det_file, [])
        detail_text = ""
        for g in gap_entries[:3]:
            detail_text += f"\n  Pre-fix qsat output: {g.get('pre_fix_details', 'N/A')[:200]}"

        detector_sections.append(f"""
### Fix {det_file} — missed {pattern['count']} {bug_type} bug(s) [{pattern['severity']}]

**Missed examples:**
{example_text}
{detail_text}

**Required change:** Strengthen the barrier certificate or detection logic in `{det_file}`
to catch {bug_type} patterns like those above. Look at the barrier polynomial and thresholds.
Consider:
- Lowering detection thresholds / tightening barrier margins
- Adding new MIR pattern recognition for the specific bug shape
- Improving the guard/check analysis to avoid false negatives
""")

    sections_text = "\n".join(detector_sections)

    return f"""You are running iteration {iteration} of the qsat bugfix improvement pipeline.
Do the ENTIRE workflow yourself without asking me anything. Work until done.

## Current Detection Performance
- Detection rate: {diagnosis['detection_rate']:.1%}
- Detected: {diagnosis['detected']} / {diagnosis['detectable']} detectable bugs
- Partial: {diagnosis['partial']} (detected pattern but not confirmed)
- Missed: {diagnosis['missed']} (failed to detect known bugs)
- Inverted: {diagnosis.get('inverted', 0)} (false positives on fixed code)

## Pathological Gaps to Fix

The following detector files have the most missed bugs:
{sections_text}

## Instructions

1. Read each detector file listed above
2. Identify the barrier certificate polynomial and/or detection logic
3. Make MINIMAL, SURGICAL changes to improve detection:
   - Tighten barrier thresholds (eps, margins, centers)
   - Add pattern recognition for missed MIR patterns
   - Strengthen guard analysis
4. Do NOT break existing detections — be conservative
5. After making changes, rebuild:
   `cd build && make -j$(sysctl -n hw.ncpu 2>/dev/null || echo 4) 2>&1 | tail -5`
6. Verify the build succeeds before finishing

## Working directories
- Detector source: src/detector_*.cpp, src/bug_detector_*.cpp
- Build: build/
- Results: results/bugfix_scan/

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
def save_results(results: List[Dict], diagnosis: Dict, iteration: int):
    """Save structured results and human-readable report."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # JSON report
    report_data = {
        "iteration": iteration,
        "timestamp": datetime.now().isoformat(),
        "diagnosis": diagnosis,
        "entries": results,
    }
    json_file = RESULTS_DIR / "bugfix_report.json"
    json_file.write_text(json.dumps(report_data, indent=2))
    log(f"JSON report: {json_file}")

    # Markdown report
    md = _generate_markdown_report(results, diagnosis, iteration)
    md_file = RESULTS_DIR / "bugfix_report.md"
    md_file.write_text(md)
    log(f"Markdown report: {md_file}")

    # Improvement prompt (latest)
    prompt = _build_improvement_prompt(diagnosis, iteration)
    prompt_file = RESULTS_DIR / "improvement_prompt.md"
    prompt_file.write_text(prompt)
    log(f"Improvement prompt: {prompt_file}")


def _generate_markdown_report(results: List[Dict], diagnosis: Dict, iteration: int) -> str:
    """Generate comprehensive markdown analysis report."""
    d = diagnosis
    patterns = d.get("pathological_patterns", [])

    # Pattern table
    pattern_rows = ""
    for p in patterns:
        examples_str = "; ".join(f"{e['repo']}({e['commit']})" for e in p["examples"][:3])
        pattern_rows += (
            f"| {p['bug_type']} | {p['count']} | {p['severity']} | "
            f"`{p['detector_file']}` | {examples_str} |\n"
        )

    # Per-classification breakdown
    by_class = defaultdict(list)
    for r in results:
        by_class[r["classification"]].append(r)

    class_details = ""
    for cls in ["DETECTED", "PARTIAL", "MISSED", "INVERTED", "INCONCLUSIVE"]:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        class_details += f"\n### {cls} ({len(entries)})\n\n"
        for e in entries[:10]:
            class_details += (
                f"- **{e['repo']}** `{e['commit'][:7]}` — {e['message'][:80]}\n"
                f"  File: `{e['file']}` | Bug type: {e['bug_type_from_commit']} | "
                f"Pre: {e['pre_fix_qsat']} → Post: {e['post_fix_qsat']}\n"
            )
        if len(entries) > 10:
            class_details += f"- ... and {len(entries) - 10} more\n"

    return f"""# qsat Bugfix Evaluation Report — Iteration {iteration}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Executive Summary

| Metric | Value |
|--------|-------|
| Total commits analyzed | {d['total_analyzed']} |
| Detectable bugs | {d['detectable']} |
| **Detection rate** | **{d['detection_rate']:.1%}** |
| Detected (BUG→SAFE) | {d['detected']} |
| Partial (BUG→BUG) | {d['partial']} |
| Missed (SAFE→SAFE) | {d['missed']} |
| Inverted (SAFE→BUG) | {d.get('inverted', 0)} |
| Inconclusive | {d['inconclusive']} |

## Pathological Patterns

Recurring weaknesses in qsat's detection, ordered by severity:

| Bug Type | Missed Count | Severity | Detector File | Example Commits |
|----------|-------------|----------|---------------|-----------------|
{pattern_rows}

## Detailed Results by Classification
{class_details}

## Root Cause Analysis

{_root_cause_section(patterns)}

## Recommendations

{_recommendations_section(patterns)}
"""


def _root_cause_section(patterns: List[Dict]) -> str:
    sections = []
    for i, p in enumerate(patterns, 1):
        sections.append(
            f"### {i}. {p['bug_type']} detection gap ({p['detector_file']})\n"
            f"- **{p['count']}** bugs missed across "
            f"{len(set(e['repo'] for e in p['examples']))} repo(s)\n"
            f"- Severity: **{p['severity']}**\n"
            f"- Likely cause: barrier certificate threshold too conservative "
            f"or missing MIR pattern recognition\n"
        )
    return "\n".join(sections) if sections else "No significant gaps identified."


def _recommendations_section(patterns: List[Dict]) -> str:
    recs = []
    for i, p in enumerate(patterns, 1):
        recs.append(
            f"{i}. **Strengthen {p['bug_type']} detection** in `{p['detector_file']}`\n"
            f"   - Tighten barrier thresholds / lower eps margins\n"
            f"   - Add pattern recognition for the specific MIR shapes seen in missed bugs\n"
        )
    return "\n".join(recs) if recs else "All detectors performing well."


# ══════════════════════════════════════════════════════════════════════════════
#  STATE MANAGEMENT — persistence across iterations
# ══════════════════════════════════════════════════════════════════════════════
def load_state() -> Dict:
    """Load pipeline state from disk."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"iterations": [], "current_iteration": 0}


def save_state(state: Dict):
    """Persist pipeline state."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def should_stop(state: Dict) -> bool:
    """Check plateau stopping condition."""
    iters = state.get("iterations", [])
    if len(iters) < PLATEAU_PATIENCE + 1:
        return False

    # Check if last PLATEAU_PATIENCE iterations had < PLATEAU_THRESHOLD improvement
    recent_rates = [it["detection_rate"] for it in iters[-(PLATEAU_PATIENCE + 1):]]
    for i in range(1, len(recent_rates)):
        delta = recent_rates[i] - recent_rates[i - 1]
        if delta >= PLATEAU_THRESHOLD:
            return False  # Still improving
    log(f"Plateau detected: last {PLATEAU_PATIENCE} iterations improved < {PLATEAU_THRESHOLD:.0%}")
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE LOOP
# ══════════════════════════════════════════════════════════════════════════════
def run_pipeline(
    specific_repo: str = "",
    max_commits: int = 50,
    max_iterations: int = DEFAULT_MAX_ITERS,
    scan_only: bool = False,
    dry_run: bool = False,
    resume: bool = False,
    model: str = "claude-sonnet-4",
):
    """Run the full scan → diagnose → improve pipeline."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    state = load_state() if resume else {"iterations": [], "current_iteration": 0}
    start_iter = state["current_iteration"] + 1 if resume else 1

    repos = discover_repos(specific_repo)
    if not repos:
        log("No repos found to scan", "ERROR")
        return 1

    log(f"Pipeline starting: {len(repos)} repo(s), max {max_iterations} iterations")
    log(f"Repos: {', '.join(r.name for r in repos)}")

    for iteration in range(start_iter, max_iterations + 1):
        state["current_iteration"] = iteration

        # ── Phase 1: SCAN ──────────────────────────────────────────────
        log_phase("SCAN", iteration)
        results = phase_scan(repos, max_commits=max_commits)

        if not results:
            log("No results from scan — most files couldn't compile to MIR", "WARN")
            log("This is expected for large projects with external dependencies")
            state["iterations"].append({
                "iteration": iteration,
                "total": 0,
                "detection_rate": 0,
                "detected": 0, "partial": 0, "missed": 0,
                "detectable": 0,
                "note": "no compilable results",
                "pathological_patterns": [],
            })
            save_state(state)
            if scan_only or iteration >= 2:
                break  # No point re-scanning if files can't compile
            continue

        # ── Phase 2: DIAGNOSE ──────────────────────────────────────────
        log_phase("DIAGNOSE", iteration)
        diagnosis = phase_diagnose(results)

        # Save results + reports
        save_results(results, diagnosis, iteration)

        state["iterations"].append({
            "iteration": iteration,
            "timestamp": datetime.now().isoformat(),
            "total": diagnosis["total_analyzed"],
            "detectable": diagnosis["detectable"],
            "detected": diagnosis["detected"],
            "partial": diagnosis["partial"],
            "missed": diagnosis["missed"],
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

        # Check stopping conditions
        if diagnosis["missed"] == 0 and diagnosis["partial"] == 0:
            log("All detectable bugs detected — pipeline complete! 🎉")
            break

        if should_stop(state):
            log("Detection rate plateau — stopping pipeline")
            break

        # ── Phase 3: IMPROVE ───────────────────────────────────────────
        log_phase("IMPROVE", iteration)
        improved = phase_improve(diagnosis, iteration, dry_run=dry_run, model=model)

        if not improved:
            log("No improvements applied — stopping pipeline")
            break

        log(f"Iteration {iteration} complete — looping for re-scan\n")

    # Final summary
    _print_summary(state)
    return 0


def _print_summary(state: Dict):
    """Print pipeline execution summary."""
    iters = state.get("iterations", [])
    print(f"\n{'='*70}")
    print("  PIPELINE SUMMARY")
    print(f"{'='*70}")
    print(f"\n{'Iter':<6} {'Total':<7} {'Detect':<8} {'Partial':<9} "
          f"{'Missed':<8} {'Rate':<8} {'Patterns'}")
    print("-" * 70)
    for it in iters:
        patterns = ", ".join(
            f"{p['bug_type']}({p['count']})"
            for p in it.get("pathological_patterns", [])
        ) or "—"
        print(f"{it['iteration']:<6} {it.get('total', 0):<7} "
              f"{it.get('detected', 0):<8} {it.get('partial', 0):<9} "
              f"{it.get('missed', 0):<8} {it.get('detection_rate', 0):<8.1%} "
              f"{patterns}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Bugfix-driven improvement pipeline for qsat")
    parser.add_argument("--repo", type=str, default="",
                        help="Specific repo path or URL to scan")
    parser.add_argument("--repo-url", type=str, default="",
                        help="GitHub URL to clone and scan")
    parser.add_argument("--max-commits", type=int, default=50,
                        help="Max bugfix commits to analyze per repo (default: 50)")
    parser.add_argument("--max-iterations", type=int, default=DEFAULT_MAX_ITERS,
                        help=f"Max pipeline iterations (default: {DEFAULT_MAX_ITERS})")
    parser.add_argument("--model", type=str, default="claude-sonnet-4",
                        help="Copilot model for improvement phase (default: claude-sonnet-4)")
    parser.add_argument("--scan-only", action="store_true",
                        help="Run scan + diagnose only, no improvements")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate prompts but don't execute copilot")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last checkpoint in pipeline_state.json")
    args = parser.parse_args()

    repo_arg = args.repo or args.repo_url or ""
    return run_pipeline(
        specific_repo=repo_arg,
        max_commits=args.max_commits,
        max_iterations=args.max_iterations,
        scan_only=args.scan_only,
        dry_run=args.dry_run,
        resume=args.resume,
        model=args.model,
    )


if __name__ == "__main__":
    sys.exit(main())
