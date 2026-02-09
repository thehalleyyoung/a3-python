#!/usr/bin/env python3
"""
Analyze all external repos using the main PythonFromScratch interface.

Runs `python -m pyfromscratch <target_dir>` for each external repo
and collects results.
"""

import subprocess
import sys
import time
import os
from pathlib import Path

# Project root
ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = ROOT / "external_tools"
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

PYTHON = sys.executable

# Map of repo name → Python source directory (relative to external_tools/<repo>/)
REPOS = {
    "Counterfit":     "counterfit",
    "DebugPy":        "src/debugpy",
    "DeepSpeed":      "deepspeed",
    "FLAML":          "flaml",
    "GraphRAG":       "graphrag",
    "Guidance":       "guidance",
    "LightGBM":       "python-package/lightgbm",
    "MSTICPY":        "msticpy",
    "ONNXRuntime":    "onnxruntime/python",
    "Presidio":       "presidio-analyzer/presidio_analyzer",
    "PromptFlow":     "src/promptflow/promptflow",
    "Qlib":           "qlib",
    "RDAgent":        "rdagent",
    "RESTler":        "restler",
    "SemanticKernel": "python/semantic_kernel",
    "django":         "django",
    "pygoat":         "pygoat",
}

# Pyright is TypeScript, codeql/codeql is not Python source - skip them


def analyze_repo(repo_name: str, src_subdir: str) -> dict:
    """Run PythonFromScratch on a single repo and capture output."""
    target = EXTERNAL / repo_name / src_subdir
    if not target.exists():
        return {
            "repo": repo_name,
            "target": str(target),
            "status": "SKIPPED",
            "reason": f"Directory not found: {target}",
            "elapsed": 0,
            "output": "",
        }

    save_path = RESULTS_DIR / f"{repo_name.lower()}_results.pkl"

    cmd = [
        PYTHON, "-m", "pyfromscratch",
        str(target),
        "--save-results", str(save_path),
    ]

    print(f"\n{'='*70}")
    print(f"  ANALYZING: {repo_name}")
    print(f"  Target:    {target}")
    print(f"{'='*70}\n")

    t0 = time.time()
    try:
        result = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=1800,  # 30 min timeout per repo
        )
        elapsed = time.time() - t0
        output = result.stdout + result.stderr
        print(output)

        return {
            "repo": repo_name,
            "target": str(target),
            "status": "OK" if result.returncode in (0, 1) else "ERROR",
            "returncode": result.returncode,
            "elapsed": elapsed,
            "output": output,
        }
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        print(f"  *** TIMEOUT after {elapsed:.0f}s ***")
        return {
            "repo": repo_name,
            "target": str(target),
            "status": "TIMEOUT",
            "elapsed": elapsed,
            "output": "",
        }
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  *** ERROR: {e} ***")
        return {
            "repo": repo_name,
            "target": str(target),
            "status": "ERROR",
            "elapsed": elapsed,
            "output": str(e),
        }


def extract_summary(output: str) -> dict:
    """Extract key numbers from the SUMMARY section of output."""
    summary = {}
    in_summary = False
    for line in output.splitlines():
        if "SUMMARY" in line and "===" in line:
            # Heuristic: next non-separator line is start of summary
            in_summary = True
            continue
        if in_summary:
            if "===" in line:
                continue
            line = line.strip()
            if not line:
                in_summary = False
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip().split()[0] if val.strip() else ""
                summary[key] = val
    return summary


def main():
    all_results = []

    total_start = time.time()

    for repo_name, src_subdir in REPOS.items():
        result = analyze_repo(repo_name, src_subdir)
        all_results.append(result)

    total_elapsed = time.time() - total_start

    # ── Grand summary ────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  GRAND SUMMARY — ALL REPOS")
    print("=" * 70)
    print(f"{'Repo':<20s} {'Status':<10s} {'Time':>8s}  {'Functions':>10s}  {'Bugs':>6s}  {'FP%':>6s}  {'TPs':>6s}")
    print("-" * 70)

    for r in all_results:
        repo = r["repo"]
        status = r["status"]
        elapsed = f"{r['elapsed']:.1f}s"
        if r["status"] in ("OK",):
            s = extract_summary(r["output"])
            funcs = s.get("Functions analysed", "?")
            bugs = s.get("Total bug instances", "?")
            fp_pct = s.get("Proven false positive", "?").split("(")[-1].rstrip(")") if "(" in s.get("Proven false positive", "") else "?"
            tps = s.get("DSE-confirmed TPs", "?")
            print(f"{repo:<20s} {status:<10s} {elapsed:>8s}  {funcs:>10s}  {bugs:>6s}  {fp_pct:>6s}  {tps:>6s}")
        else:
            reason = r.get("reason", "")
            print(f"{repo:<20s} {status:<10s} {elapsed:>8s}  {'—':>10s}  {'—':>6s}  {'—':>6s}  {'—':>6s}  {reason}")

    print("-" * 70)
    print(f"Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f} min)")
    print(f"Results saved in: {RESULTS_DIR}/")
    print()

    # Save summary to file
    summary_path = RESULTS_DIR / "all_repos_summary.txt"
    with open(summary_path, "w") as f:
        f.write("PythonFromScratch — External Repos Analysis Summary\n")
        f.write("=" * 70 + "\n\n")
        for r in all_results:
            f.write(f"--- {r['repo']} ---\n")
            f.write(f"  Status:  {r['status']}\n")
            f.write(f"  Time:    {r['elapsed']:.1f}s\n")
            if r["status"] == "OK":
                s = extract_summary(r["output"])
                for k, v in s.items():
                    f.write(f"  {k}: {v}\n")
            elif r.get("reason"):
                f.write(f"  Reason:  {r['reason']}\n")
            f.write("\n")
        f.write(f"\nTotal time: {total_elapsed:.1f}s\n")

    print(f"Summary written to {summary_path}")


if __name__ == "__main__":
    main()
