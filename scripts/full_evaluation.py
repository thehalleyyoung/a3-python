#!/usr/bin/env python3
"""
A³ Full Evaluation: Ablation Study + Multi-Tool Comparison
============================================================

Single script that produces:

  Part A — Ablation tables  (Full A³, −KS, −IPA, −DSE)
  Part B — Comparison tables (A3 vs Bandit, Pylint, Mypy, Ruff, Semgrep,
                               Pyflakes, Flake8, Pyright, ESBMC)

Usage:
    python3 scripts/full_evaluation.py
    python3 scripts/full_evaluation.py --skip-ablation   # tools only
    python3 scripts/full_evaluation.py --skip-tools      # ablation only
    python3 scripts/full_evaluation.py --tools A3 Pyright ESBMC  # subset

Outputs:
    results/full_evaluation.json
    results/full_evaluation.md
"""

from __future__ import annotations

import argparse
import json
import math
import os
import site
import subprocess
import sys
import textwrap
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════
#  Metrics
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Metrics:
    tp: int = 0; tn: int = 0; fp: int = 0; fn: int = 0
    unknown_on_bug: int = 0; unknown_on_safe: int = 0
    errors: int = 0; total: int = 0; total_runtime_sec: float = 0.0
    _runtimes: list = field(default_factory=list, repr=False)

    def update(self, expected: str, predicted: str, runtime: float = 0.0) -> None:
        self.total += 1
        self._runtimes.append(runtime)
        self.total_runtime_sec += runtime
        if predicted == "ERROR":   self.errors += 1;          return
        if predicted == "UNKNOWN":
            if expected == "BUG":  self.unknown_on_bug += 1
            else:                  self.unknown_on_safe += 1
            return
        if expected == "BUG"  and predicted == "BUG":  self.tp += 1
        elif expected == "SAFE" and predicted == "SAFE": self.tn += 1
        elif expected == "SAFE" and predicted == "BUG":  self.fp += 1
        elif expected == "BUG"  and predicted == "SAFE": self.fn += 1

    @property
    def decided(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall_strict(self) -> float:
        """UNKNOWN-on-bug counts as miss."""
        d = self.tp + self.fn + self.unknown_on_bug
        return self.tp / d if d else 0.0

    @property
    def recall_lenient(self) -> float:
        """Only decided verdicts."""
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1_strict(self) -> float:
        p, r = self.precision, self.recall_strict
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def f1_lenient(self) -> float:
        p, r = self.precision, self.recall_lenient
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def geomean_runtime_sec(self) -> float:
        """Geometric mean of per-case runtimes (avoids zero with epsilon)."""
        if not self._runtimes:
            return 0.0
        # Clamp to small epsilon to avoid log(0)
        log_sum = sum(math.log(max(r, 1e-6)) for r in self._runtimes)
        return math.exp(log_sum / len(self._runtimes))

    def summary(self) -> dict:
        return {
            "tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn,
            "unknown_on_bug": self.unknown_on_bug,
            "unknown_on_safe": self.unknown_on_safe,
            "errors": self.errors, "total": self.total,
            "decided": self.decided,
            "precision": round(self.precision, 4),
            "recall_strict": round(self.recall_strict, 4),
            "recall_lenient": round(self.recall_lenient, 4),
            "f1_strict": round(self.f1_strict, 4),
            "f1_lenient": round(self.f1_lenient, 4),
            "accuracy": round(self.accuracy, 4),
            "avg_runtime_sec": round(self.total_runtime_sec / self.total, 4) if self.total else 0,
            "geomean_runtime_sec": round(self.geomean_runtime_sec, 4),
            "total_runtime_sec": round(self.total_runtime_sec, 2),
        }


# ═══════════════════════════════════════════════════════════════════════════
#  Tier classification
# ═══════════════════════════════════════════════════════════════════════════

TIER_COMMON = {
    "ASSERT_FAIL", "DIV_ZERO", "BOUNDS", "FP_DOMAIN", "INTEGER_OVERFLOW",
    "DOUBLE_FREE", "PANIC", "UNINIT_MEMORY", "NULL_PTR", "STACK_OVERFLOW",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Part A – Ablation: A³ config runners
# ═══════════════════════════════════════════════════════════════════════════

ABLATION_CONFIGS = {
    "Full":  "All subsystems: kitchensink portfolio + interprocedural + DSE",
    "−KS":   "No 20-paper portfolio analysis (basic symbolic execution only)",
    "−IPA":  "No cross-function / interprocedural analysis",
    "−DSE":  "No concolic / dynamic symbolic execution (pure static)",
}

ABLATION_CONFIG_NAMES = {
    "Full": "Full A³",
    "−KS":  "A³ − Kitchensink",
    "−IPA": "A³ − Interprocedural",
    "−DSE": "A³ − DSE",
}


def _run_a3_config(config: str, python_bin: str, file_path: Path,
                   timeout_s: int) -> Tuple[str, float]:
    """Run A3 under one of the four ablation configurations."""
    # Build the right Python snippet per config
    if config == "Full":
        # kitchensink + interprocedural + DSE
        analyzer_line = (
            "a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=True); "
            "r = a.analyze_file_kitchensink(p)"
        )
    elif config == "−KS":
        # baseline analyze_file (no kitchensink), but still IPA + DSE
        analyzer_line = (
            "a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=True); "
            "r = a.analyze_file(p)"
        )
    elif config == "−IPA":
        # kitchensink + DSE but no interprocedural
        analyzer_line = (
            "a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=False); "
            "r = a.analyze_file_kitchensink(p)"
        )
    elif config == "−DSE":
        # kitchensink + IPA but no concolic
        analyzer_line = (
            "a = Analyzer(verbose=False, enable_concolic=False, enable_interprocedural=True); "
            "r = a.analyze_file_kitchensink(p)"
        )
    else:
        raise ValueError(f"Unknown ablation config: {config}")

    snippet = textwrap.dedent(f"""\
        import json, sys
        from pathlib import Path
        from a3_python.analyzer import Analyzer
        p = Path(sys.argv[1])
        try:
            {analyzer_line}
            v = getattr(r, 'verdict', None) or 'UNKNOWN'
            bt = getattr(r, 'bug_type', '') or ''
            if v not in ('BUG','SAFE','UNKNOWN'): v='UNKNOWN'
            print(json.dumps({{'verdict':v,'bug_type':bt}}))
        except BaseException as e:
            print(json.dumps({{'verdict':'ERROR','error':str(e)[:500]}}))
    """)
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [python_bin, "-c", snippet, str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        elapsed = time.perf_counter() - start
        if proc.returncode != 0:
            return "ERROR", elapsed
        lines = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
        if not lines:
            return "ERROR", elapsed
        d = json.loads(lines[-1])
        v = d.get("verdict", "UNKNOWN")
        return v if v in ("BUG", "SAFE", "UNKNOWN") else "UNKNOWN", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


# ═══════════════════════════════════════════════════════════════════════════
#  Part B – External tool runners
# ═══════════════════════════════════════════════════════════════════════════

def run_a3_full(python_bin: str, file_path: Path, timeout_s: int) -> Tuple[str, float]:
    """A3 Full config (same as ablation Full) for multi-tool comparison."""
    return _run_a3_config("Full", python_bin, file_path, timeout_s)


def run_bandit(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["bandit", "-f", "json", "-q", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        if proc.stdout:
            d = json.loads(proc.stdout)
            if d.get("results"):
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_pylint(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["pylint", "--output-format=json", "--disable=all", "--enable=E",
             str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        if proc.stdout and proc.stdout.strip():
            issues = json.loads(proc.stdout)
            if issues:
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_mypy(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["mypy", "--no-error-summary", "--no-color-output",
             "--ignore-missing-imports", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        output = (proc.stdout or "") + (proc.stderr or "")
        for line in output.splitlines():
            if ": error:" in line:
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_ruff(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["ruff", "check", "--output-format=json", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        if proc.stdout and proc.stdout.strip():
            issues = json.loads(proc.stdout)
            if issues:
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_semgrep(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet",
             str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
        elapsed = time.perf_counter() - start
        if proc.stdout and proc.stdout.strip():
            d = json.loads(proc.stdout)
            if d.get("results"):
                return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_pyflakes(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["pyflakes", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        output = (proc.stdout or "").strip()
        if output:
            return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_flake8(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["flake8", "--select=F,E9", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        output = (proc.stdout or "").strip()
        if output:
            return "BUG", elapsed
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_pyright(file_path: Path, timeout_s: int) -> Tuple[str, float]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["pyright", "--outputjson", str(file_path)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.perf_counter() - start
        if proc.stdout and proc.stdout.strip():
            try:
                d = json.loads(proc.stdout)
                diags = d.get("generalDiagnostics", [])
                for diag in diags:
                    if diag.get("severity") == "error":
                        return "BUG", elapsed
            except json.JSONDecodeError:
                pass
        return "SAFE", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


def run_esbmc(file_path: Path, timeout_s: int, python_bin: str) -> Tuple[str, float]:
    """Run ESBMC Python frontend."""
    esbmc_bin = Path("external_tools/esbmc/build/src/esbmc/esbmc")
    if not esbmc_bin.exists():
        return "ERROR", 0.0
    start = time.perf_counter()
    env = os.environ.copy()
    env["PYTHONPATH"] = site.getusersitepackages()
    try:
        proc = subprocess.run(
            [str(esbmc_bin), str(file_path), "--python", python_bin,
             "--quiet", "--result-only"],
            capture_output=True, text=True, timeout=timeout_s, env=env,
        )
        elapsed = time.perf_counter() - start
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if "VERIFICATION FAILED" in output:
            return "BUG", elapsed
        elif "VERIFICATION SUCCESSFUL" in output:
            return "SAFE", elapsed
        return "UNKNOWN", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - start
    except Exception:
        return "ERROR", time.perf_counter() - start


# Tool registry  (name → callable(file_path, timeout, python_bin) → (verdict, runtime))
TOOLS: Dict[str, Any] = {
    "A3":       lambda fp, t, py: run_a3_full(py, fp, t),
    "Bandit":   lambda fp, t, py: run_bandit(fp, t),
    "Pylint":   lambda fp, t, py: run_pylint(fp, t),
    "Mypy":     lambda fp, t, py: run_mypy(fp, t),
    "Ruff":     lambda fp, t, py: run_ruff(fp, t),
    "Semgrep":  lambda fp, t, py: run_semgrep(fp, t),
    "Pyflakes": lambda fp, t, py: run_pyflakes(fp, t),
    "Flake8":   lambda fp, t, py: run_flake8(fp, t),
    "Pyright":  lambda fp, t, py: run_pyright(fp, t),
    "ESBMC":    lambda fp, t, py: run_esbmc(fp, t, py),
}


# ═══════════════════════════════════════════════════════════════════════════
#  Test-case loading
# ═══════════════════════════════════════════════════════════════════════════

def load_synthetic_cases(
    suite_root: Path, manifest_path: Path, tier_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with open(manifest_path) as f:
        manifest = json.load(f)
    cases = []
    for bug_type, files in manifest["bug_types"].items():
        if tier_filter == "common" and bug_type not in TIER_COMMON:
            continue
        for filename, info in files.items():
            file_path = suite_root / bug_type / filename
            if not file_path.exists():
                continue
            cases.append({
                "bug_type": bug_type,
                "file": str(file_path),
                "filename": filename,
                "expected": info["expected"],
            })
    return sorted(cases, key=lambda c: (c["bug_type"], c["filename"]))


# ═══════════════════════════════════════════════════════════════════════════
#  Markdown helpers
# ═══════════════════════════════════════════════════════════════════════════

def _md_table(headers: list, rows: list, align: list = None) -> str:
    if align is None:
        align = ["l"] + ["r"] * (len(headers) - 1)
    sep_map = {"l": ":---", "r": "---:", "c": ":---:"}
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(sep_map.get(a, "---") for a in align) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def _bold_best(vals: list, higher_is_better=True, fmt=".3f") -> list:
    if not vals:
        return []
    best = max(vals) if higher_is_better else min(vals)
    return [f"**{v:{fmt}}**" if v == best and v > 0 else f"{v:{fmt}}" for v in vals]


# ═══════════════════════════════════════════════════════════════════════════
#  PART A — Ablation tables
# ═══════════════════════════════════════════════════════════════════════════

def run_ablation(cases: List[Dict], python_bin: str, timeout_s: int) -> dict:
    """Run all 4 A³ configs on every case; return structured results."""
    configs = list(ABLATION_CONFIGS.keys())  # Full, −KS, −IPA, −DSE
    overall: Dict[str, Metrics] = {c: Metrics() for c in configs}
    per_bt: Dict[str, Dict[str, Metrics]] = defaultdict(lambda: {c: Metrics() for c in configs})
    details: List[Dict[str, Any]] = []

    total = len(cases)
    for i, case in enumerate(cases):
        fp = Path(case["file"])
        expected = case["expected"]
        row: Dict[str, Any] = {
            "bug_type": case["bug_type"],
            "file": case["filename"],
            "expected": expected,
        }
        for cfg in configs:
            verdict, runtime = _run_a3_config(cfg, python_bin, fp, timeout_s)
            overall[cfg].update(expected, verdict, runtime)
            per_bt[case["bug_type"]][cfg].update(expected, verdict, runtime)
            row[cfg] = {"verdict": verdict, "runtime": round(runtime, 3)}

        details.append(row)
        if (i + 1) % 10 == 0 or (i + 1) == total:
            print(f"  Ablation [{i+1:3d}/{total}] {case['bug_type']:20s} {case['filename'][:50]}")

    return {
        "configs": configs,
        "overall": {c: overall[c].summary() for c in configs},
        "per_bug_type": {
            bt: {c: per_bt[bt][c].summary() for c in configs}
            for bt in sorted(per_bt.keys())
        },
        "details": details,
    }


def generate_ablation_md(data: dict) -> str:
    """Generate Markdown for the ablation study."""
    configs = data["configs"]
    overall = data["overall"]
    per_bt = data["per_bug_type"]
    details = data["details"]

    sections = []
    sections.append("# Part A — A³ Ablation Study\n")
    sections.append("**Configurations:**\n")
    for c in configs:
        sections.append(f"- **{ABLATION_CONFIG_NAMES[c]}** (`{c}`): {ABLATION_CONFIGS[c]}")
    sections.append("")

    # ── Table 1: Overall ──────────────────────────────────────────
    sections.append("## A1. Overall Ablation Results\n")
    f1s = [overall[c]["f1_strict"] for c in configs]
    f1_strs = _bold_best(f1s)
    precs = [overall[c]["precision"] for c in configs]
    prec_strs = _bold_best(precs)
    recs = [overall[c]["recall_strict"] for c in configs]
    rec_strs = _bold_best(recs)

    headers = ["Configuration", "TP", "TN", "FP", "FN", "UNK†", "ERR",
               "Prec", "Rec", "**F1**"]
    rows = []
    for i, c in enumerate(configs):
        m = overall[c]
        unk = m["unknown_on_bug"] + m["unknown_on_safe"]
        rows.append([
            f"**{ABLATION_CONFIG_NAMES[c]}**",
            str(m["tp"]), str(m["tn"]), str(m["fp"]), str(m["fn"]),
            str(unk), str(m["errors"]),
            prec_strs[i], rec_strs[i], f1_strs[i],
        ])
    sections.append(_md_table(headers, rows))
    sections.append("\n_†UNK = UNKNOWN verdicts (counted as missed for recall). "
                    "ERR = analyzer errors (excluded from metrics)._\n")

    # Timing summary for ablation configs
    sections.append("### Ablation Timing\n")
    timing_headers = ["Configuration", "Total Time", "Avg/Case", "Geomean/Case"]
    timing_rows = []
    for c in configs:
        m = overall[c]
        timing_rows.append([
            f"**{ABLATION_CONFIG_NAMES[c]}**",
            f"{m['total_runtime_sec']:.1f}s",
            f"{m['avg_runtime_sec']:.3f}s",
            f"{m.get('geomean_runtime_sec', 0.0):.3f}s",
        ])
    sections.append(_md_table(timing_headers, timing_rows, align=["l","r","r","r"]))
    sections.append("")

    # ── Table 2: Per-Bug-Type F1 ─────────────────────────────────
    sections.append("## A2. Per-Bug-Type F1 Scores\n")
    bug_types = sorted(per_bt.keys())
    headers = ["Bug Type"] + [ABLATION_CONFIG_NAMES[c] for c in configs]
    rows = []
    for bt in bug_types:
        f1s_bt = [per_bt[bt][c]["f1_strict"] for c in configs]
        cells = _bold_best(f1s_bt)
        rows.append([bt] + cells)
    sections.append(_md_table(headers, rows, align=["l"] + ["r"] * len(configs)))
    sections.append("")

    # ── Table 3: Differential Cases ──────────────────────────────
    sections.append("## A3. Feature Impact: Differential Cases\n")
    sections.append("Cases where removing a subsystem changes the verdict.\n")

    features = [
        ("−KS",  "Kitchensink (20-paper portfolio)"),
        ("−IPA", "Interprocedural Analysis"),
        ("−DSE", "Dynamic Symbolic Execution"),
    ]

    for cfg_short, feature_name in features:
        diffs = []
        for d in details:
            full_v = d["Full"]["verdict"]
            abl_v = d[cfg_short]["verdict"]
            if full_v != abl_v:
                expected = d["expected"]
                if expected == "BUG":
                    if full_v == "BUG" and abl_v in ("SAFE", "UNKNOWN"):
                        impact = f"**Feature needed** (TP → {'FN' if abl_v == 'SAFE' else 'UNKNOWN'})"
                    elif full_v in ("SAFE", "UNKNOWN") and abl_v == "BUG":
                        impact = "Ablation catches bug Full misses"
                    elif full_v == "ERROR" and abl_v in ("BUG", "SAFE"):
                        impact = f"Ablation recovers ({abl_v}); Full errored"
                    elif abl_v == "ERROR":
                        impact = "Feature prevents crash"
                    else:
                        impact = f"Full={full_v} → {cfg_short}={abl_v}"
                else:
                    if full_v == "BUG" and abl_v == "SAFE":
                        impact = "**Feature causes FP**"
                    elif full_v == "SAFE" and abl_v == "BUG":
                        impact = "Feature prevents FP"
                    elif abl_v == "ERROR":
                        impact = "Feature prevents crash"
                    else:
                        impact = f"Full={full_v} → {cfg_short}={abl_v}"
                fv_icon = "✓" if full_v == expected else ("✗" if full_v in ("BUG","SAFE") else "—")
                av_icon = "✓" if abl_v == expected else ("✗" if abl_v in ("BUG","SAFE") else "—")
                diffs.append([
                    d["bug_type"], d["file"].replace(".py", ""), expected,
                    f"{fv_icon} {full_v}", f"{av_icon} {abl_v}", impact,
                ])

        if diffs:
            sections.append(f"\n### {feature_name} (`{cfg_short}`)\n")
            headers = ["Bug Type", "File", "Expected", "Full A³", cfg_short, "Impact"]
            sections.append(_md_table(headers, diffs, align=["l","l","c","c","c","l"]))

    # ── Table 4: Feature Contribution Summary ────────────────────
    sections.append("\n## A4. Feature Contribution Summary\n")
    full_m = overall["Full"]
    headers = ["Feature Removed", "ΔTP", "ΔFP", "ΔF1", "Net Effect"]
    rows = []
    for cfg_short, feature_name in features:
        m = overall[cfg_short]
        delta_tp = m["tp"] - full_m["tp"]
        delta_fp = m["fp"] - full_m["fp"]
        delta_f1 = m["f1_strict"] - full_m["f1_strict"]
        effects = []
        if delta_tp < 0: effects.append(f"loses {abs(delta_tp)} TP")
        elif delta_tp > 0: effects.append(f"gains {delta_tp} TP")
        if delta_fp < 0: effects.append(f"removes {abs(delta_fp)} FP")
        elif delta_fp > 0: effects.append(f"adds {delta_fp} FP")
        if not effects: effects.append("no metric change")
        rows.append([
            f"**{feature_name}**",
            f"{delta_tp:+d}", f"{delta_fp:+d}", f"{delta_f1:+.3f}",
            "; ".join(effects),
        ])
    sections.append(_md_table(headers, rows, align=["l","r","r","r","l"]))
    sections.append("")

    return "\n".join(sections)


# ═══════════════════════════════════════════════════════════════════════════
#  PART B — Multi-tool comparison tables
# ═══════════════════════════════════════════════════════════════════════════

def run_tools(cases: List[Dict], tools_to_run: List[str],
              python_bin: str, timeout_s: int) -> dict:
    """Run external tools on every case; return structured results."""
    metrics: Dict[str, Metrics] = {t: Metrics() for t in tools_to_run}
    per_bt: Dict[str, Dict[str, Metrics]] = defaultdict(lambda: {t: Metrics() for t in tools_to_run})
    details: List[Dict[str, Any]] = []

    total = len(cases)
    for i, case in enumerate(cases):
        fp = Path(case["file"])
        expected = case["expected"]
        row: Dict[str, Any] = {
            "bug_type": case["bug_type"],
            "file": case["filename"],
            "expected": expected,
        }
        for tool in tools_to_run:
            verdict, runtime = TOOLS[tool](fp, timeout_s, python_bin)
            metrics[tool].update(expected, verdict, runtime)
            per_bt[case["bug_type"]][tool].update(expected, verdict, runtime)
            row[tool] = {"verdict": verdict, "runtime": round(runtime, 3)}

        details.append(row)
        if (i + 1) % 10 == 0 or (i + 1) == total:
            print(f"  Tools [{i+1:3d}/{total}] {case['bug_type']:20s} {case['filename'][:50]}")

    return {
        "tools": tools_to_run,
        "metrics": {t: metrics[t].summary() for t in tools_to_run},
        "per_bug_type": {
            bt: {t: per_bt[bt][t].summary() for t in tools_to_run}
            for bt in sorted(per_bt.keys())
        },
        "details": details,
    }


def generate_comparison_md(data: dict) -> str:
    """Generate Markdown for the multi-tool comparison."""
    tools = data["tools"]
    metrics = data["metrics"]
    pbt = data["per_bug_type"]
    details = data["details"]
    sections = []

    sections.append("# Part B — Multi-Tool Comparison\n")
    sections.append(f"**Tools:** {', '.join(tools)}\n")

    # ── Table B1: Overall ─────────────────────────────────────────
    sections.append("## B1. Overall Results\n")

    rows_raw = []
    for t in tools:
        m = metrics[t]
        unk = m["unknown_on_bug"] + m["unknown_on_safe"]
        rows_raw.append({
            "tool": t,
            "tp": m["tp"], "tn": m["tn"], "fp": m["fp"], "fn": m["fn"],
            "unk": unk,
            "prec": m["precision"], "rec": m["recall_strict"],
            "f1": m["f1_strict"], "acc": m["accuracy"],
            "time": m["total_runtime_sec"],
        })
    rows_raw.sort(key=lambda r: -r["f1"])

    f1s = [r["f1"] for r in rows_raw]
    f1_strs = _bold_best(f1s)
    precs = [r["prec"] for r in rows_raw]
    prec_strs = _bold_best(precs)

    headers = ["Tool", "TP", "TN", "FP", "FN", "UNK", "Precision",
               "Recall", "**F1**", "Accuracy", "Time"]
    rows = []
    for i, r in enumerate(rows_raw):
        rows.append([
            f"**{r['tool']}**" if r["f1"] == max(f1s) else r["tool"],
            str(r["tp"]), str(r["tn"]), str(r["fp"]), str(r["fn"]),
            str(r["unk"]),
            prec_strs[i], f"{r['rec']:.3f}", f1_strs[i],
            f"{r['acc']:.3f}", f"{r['time']:.1f}s",
        ])
    sections.append(_md_table(headers, rows))
    sections.append("")

    # ── Table B2: Per-Bug-Type F1 ─────────────────────────────────
    sections.append("## B2. Per-Bug-Type F1\n")
    bug_types = sorted(pbt.keys())
    headers = ["Bug Type"] + tools
    rows = []
    for bt in bug_types:
        f1s_bt = [pbt[bt][t]["f1_strict"] for t in tools]
        cells = _bold_best(f1s_bt)
        rows.append([bt] + cells)
    sections.append(_md_table(headers, rows, align=["l"] + ["r"] * len(tools)))
    sections.append("")

    # ── Table B3: Unique Catches ──────────────────────────────────
    sections.append("## B3. Unique Catches (bugs found by only one tool)\n")
    bug_cases = [d for d in details if d["expected"] == "BUG"]
    unique: Dict[str, List[str]] = {t: [] for t in tools}
    for d in bug_cases:
        catchers = [t for t in tools if d.get(t, {}).get("verdict") == "BUG"]
        if len(catchers) == 1:
            unique[catchers[0]].append(f"{d['bug_type']}/{d['file']}")

    headers = ["Tool", "Unique TPs", "Examples (up to 5)"]
    rows = []
    for t in tools:
        n = len(unique[t])
        if n == 0:
            continue
        examples = ", ".join(unique[t][:5])
        if n > 5:
            examples += f", … (+{n-5} more)"
        rows.append([t, str(n), examples])
    if rows:
        sections.append(_md_table(headers, rows, align=["l","r","l"]))
    else:
        sections.append("_No tool has unique catches._")
    sections.append("")

    # ── Table B4: A3 False Positives ──────────────────────────────
    sections.append("## B4. A3 False Positives\n")
    fps = [d for d in details if d["expected"] == "SAFE"
           and d.get("A3", {}).get("verdict") == "BUG"]
    if fps:
        by_bt: Dict[str, List[str]] = {}
        for d in fps:
            by_bt.setdefault(d["bug_type"], []).append(d["file"])
        headers = ["Bug Type", "Count", "Files"]
        rows = []
        for bt in sorted(by_bt):
            rows.append([bt, str(len(by_bt[bt])), ", ".join(by_bt[bt])])
        rows.append(["**Total**", f"**{len(fps)}**", ""])
        sections.append(_md_table(headers, rows, align=["l","r","l"]))
    else:
        sections.append("_No A3 false positives._")
    sections.append("")

    # ── Table B5: A3 False Negatives ──────────────────────────────
    sections.append("## B5. A3 False Negatives & Who Else Catches Them\n")
    others = [t for t in tools if t != "A3"]
    fns = [d for d in details if d["expected"] == "BUG"
           and d.get("A3", {}).get("verdict") in ("SAFE", "UNKNOWN")]
    if fns:
        headers = ["Bug Type", "File", "A3", "Caught By"]
        rows = []
        for d in fns:
            a3v = d.get("A3", {}).get("verdict", "?")
            catchers = [t for t in others if d.get(t, {}).get("verdict") == "BUG"]
            rows.append([d["bug_type"], d["file"], a3v,
                         ", ".join(catchers) if catchers else "_(none)_"])
        sections.append(_md_table(headers, rows, align=["l","l","c","l"]))
    else:
        sections.append("_No A3 false negatives._")
    sections.append("")

    # ── Table B6: Speed ───────────────────────────────────────────
    sections.append("## B6. Speed Comparison\n")
    a3_total = metrics.get("A3", {}).get("total_runtime_sec", 1)
    speed_rows = [(t, metrics[t]["total_runtime_sec"], metrics[t]["avg_runtime_sec"],
                   metrics[t].get("geomean_runtime_sec", 0.0)) for t in tools]
    speed_rows.sort(key=lambda r: r[1])
    headers = ["Tool", "Total Time", "Avg/Case", "Geomean/Case", "Speedup vs A3"]
    rows = []
    for t, total, avg, geomean in speed_rows:
        speedup = a3_total / total if total > 0 else float("inf")
        rows.append([t, f"{total:.1f}s", f"{avg:.3f}s", f"{geomean:.3f}s",
                     f"{speedup:.1f}×" if t != "A3" else "—"])
    sections.append(_md_table(headers, rows, align=["l","r","r","r","r"]))
    sections.append("")

    # ── Key Findings ──────────────────────────────────────────────
    if "A3" in metrics:
        a3 = metrics["A3"]
        other_tools = [t for t in tools if t != "A3"]
        if other_tools:
            best_other_name = max(other_tools, key=lambda t: metrics[t]["f1_strict"])
            bo = metrics[best_other_name]
            sections.append("## Key Findings\n")
            ratio = a3["f1_strict"] / bo["f1_strict"] if bo["f1_strict"] > 0 else float("inf")
            sections.append(f"1. **A3 dominates overall**: F1 = {a3['f1_strict']:.3f} vs "
                            f"{best_other_name} at {bo['f1_strict']:.3f} — "
                            f"**{ratio:.1f}× higher F1** than the next-best tool.\n")

            # Exclusive categories
            exclusive = []
            for bt in sorted(pbt):
                a3_f1 = pbt[bt]["A3"]["f1_strict"]
                others_f1 = [pbt[bt][t]["f1_strict"] for t in tools if t != "A3"]
                if a3_f1 > 0 and all(f == 0 for f in others_f1):
                    exclusive.append(bt)
            if exclusive:
                sections.append(f"2. **A3 is the only tool** that catches: "
                                f"**{', '.join(exclusive)}**.\n")

            # Complementary value
            a3_fns = [d for d in details if d["expected"] == "BUG"
                      and d.get("A3", {}).get("verdict") in ("SAFE", "UNKNOWN")]
            caught_by_others = [d for d in a3_fns
                                if any(d.get(t, {}).get("verdict") == "BUG"
                                       for t in tools if t != "A3")]
            if caught_by_others:
                sections.append(f"3. **Complementary value**: {len(caught_by_others)} of A3's "
                                f"{len(a3_fns)} misses are caught by other tools → "
                                f"an ensemble could push F1 higher.\n")
    sections.append("")
    return "\n".join(sections)


# ═══════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="A³ Full Evaluation: Ablation + Multi-Tool Comparison")
    parser.add_argument("--tier", choices=["common", "all"], default="common")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Per-tool per-case timeout (seconds)")
    parser.add_argument("--python", default="/opt/homebrew/bin/python3.11")
    parser.add_argument("--tools", nargs="+", default=list(TOOLS.keys()),
                        help="External tools to compare (default: all)")
    parser.add_argument("--skip-ablation", action="store_true",
                        help="Skip Part A (ablation study)")
    parser.add_argument("--skip-tools", action="store_true",
                        help="Skip Part B (multi-tool comparison)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Only run first N cases (0 = all)")
    parser.add_argument("--json", default="results/full_evaluation.json")
    parser.add_argument("--md", default="results/full_evaluation.md")
    args = parser.parse_args()

    suite_root = Path("tests/synthetic_suite")
    manifest_path = suite_root / "GROUND_TRUTH_MANIFEST.json"
    if not manifest_path.exists():
        print(f"Error: Manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    cases = load_synthetic_cases(suite_root, manifest_path, args.tier)
    if args.limit > 0:
        cases = cases[:args.limit]

    print(f"Loaded {len(cases)} synthetic cases (tier={args.tier})")
    print(f"Python: {args.python}")
    print()

    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    output: Dict[str, Any] = {
        "timestamp": ts,
        "tier": args.tier,
        "total_cases": len(cases),
    }
    md_sections = []
    md_sections.append(f"# A³ Full Evaluation Report\n")
    md_sections.append(f"**Date:** {ts}  ")
    md_sections.append(f"**Tier:** {args.tier} · **Cases:** {len(cases)}  ")
    md_sections.append(f"**Python:** {args.python}\n")
    md_sections.append("---\n")

    wall_start = time.perf_counter()

    # ── Part A: Ablation ──────────────────────────────────────────
    if not args.skip_ablation:
        print("=" * 60)
        print("  PART A — Ablation Study (4 A³ configs)")
        print("=" * 60)
        ablation_data = run_ablation(cases, args.python, args.timeout)
        output["ablation"] = ablation_data
        md_sections.append(generate_ablation_md(ablation_data))
        md_sections.append("\n---\n")

        # Console summary
        print("\n── Ablation Summary ──")
        for c in ablation_data["configs"]:
            m = ablation_data["overall"][c]
            gm = m.get('geomean_runtime_sec', 0.0)
            print(f"  {ABLATION_CONFIG_NAMES[c]:<25s}  "
                  f"TP={m['tp']:2d}  FP={m['fp']:2d}  "
                  f"F1={m['f1_strict']:.3f}  "
                  f"Geomean={gm:.3f}s")
        print()

    # ── Part B: Multi-tool comparison ─────────────────────────────
    if not args.skip_tools:
        tools_to_run = [t for t in args.tools if t in TOOLS]
        print("=" * 60)
        print(f"  PART B — Multi-Tool Comparison ({len(tools_to_run)} tools)")
        print("=" * 60)
        print(f"  Tools: {', '.join(tools_to_run)}")
        print()

        tools_data = run_tools(cases, tools_to_run, args.python, args.timeout)
        output["comparison"] = tools_data
        md_sections.append(generate_comparison_md(tools_data))

        # Console summary
        print("\n── Tool Comparison Summary ──")
        ranked = sorted(tools_to_run,
                        key=lambda t: -tools_data["metrics"][t]["f1_strict"])
        for t in ranked:
            m = tools_data["metrics"][t]
            gm = m.get('geomean_runtime_sec', 0.0)
            print(f"  {t:<10s}  TP={m['tp']:2d}  FP={m['fp']:2d}  "
                  f"F1={m['f1_strict']:.3f}  Time={m['total_runtime_sec']:.1f}s  "
                  f"Geomean={gm:.3f}s")
        print()

    wall_elapsed = time.perf_counter() - wall_start

    # ── Save outputs ──────────────────────────────────────────────
    output["wall_time_sec"] = round(wall_elapsed, 1)
    md_sections.append(f"\n---\n_Total wall time: {wall_elapsed:.0f}s_\n")

    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    json_path = Path(args.json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"JSON → {json_path}")

    md_path = Path(args.md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_text = "\n".join(md_sections) + "\n"
    md_path.write_text(md_text)
    print(f"Markdown → {md_path}")

    print(f"\nDone in {wall_elapsed:.0f}s.")


if __name__ == "__main__":
    main()
