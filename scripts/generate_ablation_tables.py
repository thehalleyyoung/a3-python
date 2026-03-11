#!/usr/bin/env python3
"""
A³ Ablation Table Generator
============================

Runs 4 ablation configurations on the synthetic benchmark suite and
generates Markdown tables highlighting cases where disabling a
subsystem changes the verdict.

Configurations:
  1. Full A³            – kitchensink + interprocedural + DSE
  2. A³ − Kitchensink   – no portfolio/20-paper analysis
  3. A³ − Interprocedural – no cross-function analysis
  4. A³ − DSE           – no concolic/dynamic symbolic execution

Usage:
    python3 scripts/generate_ablation_tables.py [--timeout 30] [--tier common]
    python3 scripts/generate_ablation_tables.py --json results/ablation_synthetic.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─── Paths ───────────────────────────────────────────────────────────────

A3_ROOT = Path(__file__).resolve().parent.parent
SUITE_ROOT = A3_ROOT / "tests" / "synthetic_suite"
MANIFEST = SUITE_ROOT / "GROUND_TRUTH_MANIFEST.json"
PYTHON = sys.executable  # use the same python running this script

TIER_COMMON = {
    "ASSERT_FAIL", "DIV_ZERO", "BOUNDS", "FP_DOMAIN", "INTEGER_OVERFLOW",
    "DOUBLE_FREE", "PANIC", "UNINIT_MEMORY", "NULL_PTR", "STACK_OVERFLOW",
}


# ─── Ablation configs ───────────────────────────────────────────────────

@dataclass
class AblationConfig:
    name: str
    short: str
    cli_flags: List[str]
    description: str


CONFIGS = [
    AblationConfig(
        name="Full A³",
        short="Full",
        cli_flags=[
            "--functions", "--interprocedural", "--dse-verify",
            "--deduplicate", "--min-confidence", "0.3",
        ],
        description="All features: kitchensink + interprocedural + DSE",
    ),
    AblationConfig(
        name="A³ − Kitchensink",
        short="−KS",
        cli_flags=[
            "--no-kitchensink",
            "--functions", "--interprocedural", "--dse-verify",
            "--deduplicate", "--min-confidence", "0.3",
        ],
        description="No 20-paper portfolio analysis (basic symbolic + BMC only)",
    ),
    AblationConfig(
        name="A³ − Interprocedural",
        short="−IPA",
        cli_flags=[
            "--functions",
            "--deduplicate", "--min-confidence", "0.3",
        ],
        description="No call graph / taint summaries / cross-function analysis",
    ),
    AblationConfig(
        name="A³ − DSE",
        short="−DSE",
        cli_flags=[
            "--no-concolic",
            "--functions", "--interprocedural",
            "--deduplicate", "--min-confidence", "0.3",
        ],
        description="No concolic / dynamic symbolic execution (pure static)",
    ),
]


# ─── Metrics ─────────────────────────────────────────────────────────────

@dataclass
class Metrics:
    tp: int = 0; tn: int = 0; fp: int = 0; fn: int = 0
    unknown_on_bug: int = 0; unknown_on_safe: int = 0
    total: int = 0; total_runtime_sec: float = 0.0

    def update(self, expected: str, predicted: str, runtime: float):
        self.total += 1
        self.total_runtime_sec += runtime
        if predicted == "UNKNOWN":
            if expected == "BUG":
                self.unknown_on_bug += 1
            else:
                self.unknown_on_safe += 1
            return
        if predicted == "ERROR":
            return
        if expected == "BUG" and predicted == "BUG":
            self.tp += 1
        elif expected == "SAFE" and predicted == "SAFE":
            self.tn += 1
        elif expected == "SAFE" and predicted == "BUG":
            self.fp += 1
        elif expected == "BUG" and predicted == "SAFE":
            self.fn += 1

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn + self.unknown_on_bug
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def summary(self) -> dict:
        return {
            "tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn,
            "unknown_on_bug": self.unknown_on_bug,
            "unknown_on_safe": self.unknown_on_safe,
            "total": self.total,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "total_runtime_sec": round(self.total_runtime_sec, 2),
        }


# ─── Runner ──────────────────────────────────────────────────────────────

# Python snippets for each ablation configuration.
# Each snippet imports the Analyzer and invokes it with specific settings.
# Output: a JSON line with {"verdict": "BUG"|"SAFE"|"UNKNOWN"|"ERROR"}.

_SNIPPET_FULL = """\
import json, sys
from pathlib import Path
from a3_python.analyzer import Analyzer
p = Path(sys.argv[1])
try:
    a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=True)
    r = a.analyze_file_kitchensink(p)
    v = getattr(r, 'verdict', None) or 'UNKNOWN'
    if v not in ('BUG','SAFE','UNKNOWN'): v='UNKNOWN'
    print(json.dumps({'verdict':v}))
except Exception as e:
    print(json.dumps({'verdict':'ERROR','error':str(e)[:300]}))
"""

_SNIPPET_NO_KS = """\
import json, sys
from pathlib import Path
from a3_python.analyzer import Analyzer
p = Path(sys.argv[1])
try:
    a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=True)
    r = a.analyze_file(p)
    v = getattr(r, 'verdict', None) or 'UNKNOWN'
    if v not in ('BUG','SAFE','UNKNOWN'): v='UNKNOWN'
    print(json.dumps({'verdict':v}))
except Exception as e:
    print(json.dumps({'verdict':'ERROR','error':str(e)[:300]}))
"""

_SNIPPET_NO_IPA = """\
import json, sys
from pathlib import Path
from a3_python.analyzer import Analyzer
p = Path(sys.argv[1])
try:
    a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=False)
    r = a.analyze_file_kitchensink(p)
    v = getattr(r, 'verdict', None) or 'UNKNOWN'
    if v not in ('BUG','SAFE','UNKNOWN'): v='UNKNOWN'
    print(json.dumps({'verdict':v}))
except Exception as e:
    print(json.dumps({'verdict':'ERROR','error':str(e)[:300]}))
"""

_SNIPPET_NO_DSE = """\
import json, sys
from pathlib import Path
from a3_python.analyzer import Analyzer
p = Path(sys.argv[1])
try:
    a = Analyzer(verbose=False, enable_concolic=False, enable_interprocedural=True)
    r = a.analyze_file_kitchensink(p)
    v = getattr(r, 'verdict', None) or 'UNKNOWN'
    if v not in ('BUG','SAFE','UNKNOWN'): v='UNKNOWN'
    print(json.dumps({'verdict':v}))
except Exception as e:
    print(json.dumps({'verdict':'ERROR','error':str(e)[:300]}))
"""

CONFIG_SNIPPETS = {
    "Full A³": _SNIPPET_FULL,
    "A³ − Kitchensink": _SNIPPET_NO_KS,
    "A³ − Interprocedural": _SNIPPET_NO_IPA,
    "A³ − DSE": _SNIPPET_NO_DSE,
}


def run_a3(filepath: Path, config: AblationConfig, timeout_s: int) -> Tuple[str, float]:
    """Run A3 with a specific ablation config via Python API. Returns (verdict, seconds)."""
    t0 = time.perf_counter()
    snippet = CONFIG_SNIPPETS[config.name]
    try:
        proc = subprocess.run(
            [PYTHON, "-c", snippet, str(filepath)],
            capture_output=True, text=True, timeout=timeout_s,
            cwd=str(A3_ROOT),
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        elapsed = time.perf_counter() - t0
        # Parse last JSON line from stdout
        lines = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
        if not lines:
            return "ERROR", elapsed
        try:
            d = json.loads(lines[-1])
        except json.JSONDecodeError:
            return "ERROR", elapsed
        v = d.get("verdict", "UNKNOWN")
        return v if v in ("BUG", "SAFE", "UNKNOWN") else "UNKNOWN", elapsed
    except subprocess.TimeoutExpired:
        return "UNKNOWN", time.perf_counter() - t0
    except Exception:
        return "ERROR", time.perf_counter() - t0


# ─── Case loading ────────────────────────────────────────────────────────

def load_cases(tier: str) -> List[Dict[str, Any]]:
    with open(MANIFEST) as f:
        manifest = json.load(f)
    cases = []
    for bt, files in manifest["bug_types"].items():
        if tier == "common" and bt not in TIER_COMMON:
            continue
        for fname, info in files.items():
            fp = SUITE_ROOT / bt / fname
            if not fp.exists():
                continue
            cases.append({
                "bug_type": bt, "filename": fname,
                "file": str(fp), "expected": info["expected"],
            })
    return sorted(cases, key=lambda c: (c["bug_type"], c["filename"]))


# ─── Table generators ───────────────────────────────────────────────────

def _md_table(headers, rows, align=None):
    if align is None:
        align = ["l"] + ["r"] * (len(headers) - 1)
    sep_map = {"l": ":---", "r": "---:", "c": ":---:"}
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(sep_map.get(a, "---") for a in align) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def _bold_max(vals, fmt=".3f"):
    mx = max(vals) if vals else 0
    return [f"**{v:{fmt}}**" if v == mx and v > 0 else f"{v:{fmt}}" for v in vals]


def generate_tables(details, metrics_by_config, per_bt_metrics):
    sections = []
    configs = [c.name for c in CONFIGS]
    config_shorts = {c.name: c.short for c in CONFIGS}

    # ── Table 1: Overall Metrics ──────────────────────────────────
    sections.append("## Overall Ablation Results\n")
    headers = ["Configuration", "TP", "TN", "FP", "FN", "UNK", "Prec", "Rec", "**F1**", "Acc", "Time"]
    rows = []
    f1s = [metrics_by_config[c].f1 for c in configs]
    f1_strs = _bold_max(f1s)
    for i, c in enumerate(configs):
        m = metrics_by_config[c]
        unk = m.unknown_on_bug + m.unknown_on_safe
        rows.append([
            f"**{c}**" if m.f1 == max(f1s) else c,
            str(m.tp), str(m.tn), str(m.fp), str(m.fn), str(unk),
            f"{m.precision:.3f}", f"{m.recall:.3f}", f1_strs[i],
            f"{m.accuracy:.3f}", f"{m.total_runtime_sec:.1f}s",
        ])
    sections.append(_md_table(headers, rows))

    # ── Table 2: Per-Bug-Type F1 ─────────────────────────────────
    sections.append("\n## Per-Bug-Type F1\n")
    bug_types = sorted(per_bt_metrics.keys())
    headers = ["Bug Type"] + [config_shorts[c] for c in configs]
    rows = []
    for bt in bug_types:
        f1s_bt = [per_bt_metrics[bt][c].f1 for c in configs]
        cells = _bold_max(f1s_bt)
        rows.append([bt] + cells)
    sections.append(_md_table(headers, rows, align=["l"] + ["r"] * len(configs)))

    # ── Table 3: Differential Cases ──────────────────────────────
    # Cases where removing a feature changes the verdict
    sections.append("\n## Feature Impact: Cases Where Ablation Changes the Verdict\n")
    diffs = _find_differentials(details, configs)

    if diffs:
        for feature, desc, cases in diffs:
            sections.append(f"\n### {feature}\n")
            sections.append(f"_{desc}_\n")
            headers_diff = ["Bug Type", "File", "Expected", "Full", feature, "Impact"]
            rows_diff = []
            for d in cases:
                rows_diff.append([
                    d["bug_type"],
                    d["filename"],
                    d["expected"],
                    _verdict_icon(d["full_verdict"], d["expected"]),
                    _verdict_icon(d["ablated_verdict"], d["expected"]),
                    d["impact"],
                ])
            sections.append(_md_table(headers_diff, rows_diff, align=["l", "l", "c", "c", "c", "l"]))
    else:
        sections.append("_No verdict changes detected across ablation configs._\n")

    # ── Table 4: Summary of Feature Contributions ────────────────
    sections.append("\n## Feature Contribution Summary\n")
    contrib = _feature_contributions(details, metrics_by_config, configs)
    headers = ["Feature Removed", "F1 Drop", "TP Lost", "FP Gained", "Net Impact"]
    rows = []
    for feat, info in contrib:
        rows.append([
            feat,
            f"{info['f1_drop']:+.3f}",
            str(info['tp_lost']),
            str(info['fp_gained']),
            info['description'],
        ])
    sections.append(_md_table(headers, rows, align=["l", "r", "r", "r", "l"]))

    return "\n".join(sections)


def _verdict_icon(verdict, expected):
    """Return a verdict with check/cross icon."""
    correct = (verdict == expected) or (verdict == "BUG" and expected == "BUG") or (verdict == "SAFE" and expected == "SAFE")
    icon = "✓" if correct else "✗"
    return f"{icon} {verdict}"


def _find_differentials(details, configs):
    """Find cases where ablating a feature changes the verdict vs Full."""
    full = configs[0]
    ablated_configs = [
        ("−Kitchensink", CONFIGS[1].name, "Kitchensink (20-paper portfolio) disabled"),
        ("−Interprocedural", CONFIGS[2].name, "Interprocedural analysis disabled"),
        ("−DSE", CONFIGS[3].name, "Dynamic Symbolic Execution disabled"),
    ]

    results = []
    for feature_label, config_name, desc in ablated_configs:
        cases = []
        for d in details:
            full_v = d.get(full, {}).get("verdict", "?")
            abl_v = d.get(config_name, {}).get("verdict", "?")
            if full_v != abl_v and full_v not in ("ERROR", "?") and abl_v not in ("ERROR", "?"):
                # Determine impact
                expected = d["expected"]
                if full_v == expected and abl_v != expected:
                    impact = f"Feature needed (→ {'FN' if expected == 'BUG' else 'FP'})"
                elif abl_v == expected and full_v != expected:
                    impact = f"Feature hurts (→ {'FP' if expected == 'SAFE' else 'FN'})"
                elif full_v == "BUG" and abl_v == "SAFE":
                    impact = "Bug lost"
                elif full_v == "SAFE" and abl_v == "BUG":
                    impact = "False alarm gained"
                elif full_v == "UNKNOWN":
                    impact = "Became decided"
                elif abl_v == "UNKNOWN":
                    impact = "Became undecided"
                else:
                    impact = f"{full_v} → {abl_v}"

                cases.append({
                    "bug_type": d["bug_type"],
                    "filename": d["filename"],
                    "expected": expected,
                    "full_verdict": full_v,
                    "ablated_verdict": abl_v,
                    "impact": impact,
                })
        if cases:
            results.append((feature_label, desc, cases))
    return results


def _feature_contributions(details, metrics_by_config, configs):
    """Summarize the impact of each feature removal."""
    full = configs[0]
    full_m = metrics_by_config[full]

    contributions = []
    for cfg in CONFIGS[1:]:
        m = metrics_by_config[cfg.name]
        f1_drop = m.f1 - full_m.f1
        tp_lost = full_m.tp - m.tp
        fp_gained = m.fp - full_m.fp
        if f1_drop < 0:
            desc = f"F1 drops by {abs(f1_drop):.3f} — feature improves detection"
        elif f1_drop > 0:
            desc = f"F1 rises by {f1_drop:.3f} — feature may cause over-reporting"
        else:
            desc = "No impact on F1"
        contributions.append((cfg.short, {
            "f1_drop": f1_drop,
            "tp_lost": tp_lost,
            "fp_gained": fp_gained,
            "description": desc,
        }))
    return contributions


# ─── Main ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="A³ Ablation Table Generator")
    parser.add_argument("--tier", choices=["common", "all"], default="common")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--out", default="results/ablation_tables.md")
    parser.add_argument("--json", default="results/ablation_synthetic.json")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    cases = load_cases(args.tier)
    if args.limit > 0:
        cases = cases[:args.limit]

    print(f"Loaded {len(cases)} cases (tier={args.tier})")
    print(f"Configurations: {', '.join(c.short for c in CONFIGS)}")
    print(f"Timeout: {args.timeout}s per config per case")
    print()

    # Run all configs on all cases
    metrics_by_config = {c.name: Metrics() for c in CONFIGS}
    per_bt_metrics: Dict[str, Dict[str, Metrics]] = {}
    details: List[Dict[str, Any]] = []

    total = len(cases) * len(CONFIGS)
    done = 0

    for i, case in enumerate(cases):
        fp = Path(case["file"])
        expected = case["expected"]
        row = {
            "bug_type": case["bug_type"],
            "filename": case["filename"],
            "expected": expected,
        }

        for cfg in CONFIGS:
            verdict, runtime = run_a3(fp, cfg, args.timeout)
            metrics_by_config[cfg.name].update(expected, verdict, runtime)

            bt = case["bug_type"]
            if bt not in per_bt_metrics:
                per_bt_metrics[bt] = {c.name: Metrics() for c in CONFIGS}
            per_bt_metrics[bt][cfg.name].update(expected, verdict, runtime)

            row[cfg.name] = {"verdict": verdict, "runtime": round(runtime, 3)}
            done += 1

        details.append(row)

        # Progress
        if (i + 1) % 5 == 0 or (i + 1) == len(cases):
            pct = done / total * 100
            print(f"  [{i+1:3d}/{len(cases)}] {pct:5.1f}%  {case['bug_type']:20s} {case['filename'][:50]}")

    print()

    # Generate tables
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    md_sections = [
        f"# A³ Ablation Study — Synthetic Suite\n",
        f"**Date:** {ts}  ",
        f"**Tier:** {args.tier} · **Cases:** {len(cases)}  ",
        f"**Timeout:** {args.timeout}s per config per case\n",
        "**Configurations:**\n",
    ]
    for cfg in CONFIGS:
        md_sections.append(f"- **{cfg.name}** ({cfg.short}): {cfg.description}")
    md_sections.append("")

    md_sections.append(generate_tables(details, metrics_by_config, per_bt_metrics))

    md = "\n".join(md_sections) + "\n"

    # Save markdown
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md)
    print(md)
    print(f"\n--- Saved Markdown to {out_path} ---")

    # Save JSON
    json_data = {
        "timestamp": ts,
        "tier": args.tier,
        "total_cases": len(cases),
        "configs": [{"name": c.name, "short": c.short, "flags": c.cli_flags, "desc": c.description} for c in CONFIGS],
        "metrics": {c.name: metrics_by_config[c.name].summary() for c in CONFIGS},
        "per_bug_type": {
            bt: {c.name: per_bt_metrics[bt][c.name].summary() for c in CONFIGS}
            for bt in sorted(per_bt_metrics.keys())
        },
        "details": details,
    }
    json_path = Path(args.json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2, default=str)
    print(f"--- Saved JSON to {json_path} ---")


if __name__ == "__main__":
    main()
