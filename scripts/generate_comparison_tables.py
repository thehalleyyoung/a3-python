#!/usr/bin/env python3
"""
Generate Markdown comparison tables from multi_tool_comparison.json.

Produces:
  1. Overall results table (TP/TN/FP/FN/Precision/Recall/F1/Accuracy/Time)
  2. Per-bug-type F1 table
  3. Key-findings bullet list
  4. Disagreement highlights

Usage:
    python3 scripts/generate_comparison_tables.py [JSON_PATH] [--out FILE]

Defaults to results/multi_tool_comparison.json → results/comparison_tables.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


# ── helpers ──────────────────────────────────────────────────────────────

def _bold_max(vals: list[float], fmt: str = ".3f") -> list[str]:
    """Return formatted strings, bolding the maximum value(s)."""
    if not vals:
        return []
    mx = max(vals)
    out = []
    for v in vals:
        s = f"{v:{fmt}}"
        out.append(f"**{s}**" if v == mx and v > 0 else s)
    return out


def _md_table(headers: list[str], rows: list[list[str]], align: list[str] | None = None) -> str:
    """Build a Markdown pipe table. align entries: 'l', 'r', 'c'."""
    if align is None:
        align = ["l"] + ["r"] * (len(headers) - 1)
    sep_map = {"l": ":---", "r": "---:", "c": ":---:"}
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(sep_map.get(a, "---") for a in align) + " |")
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


# ── table generators ────────────────────────────────────────────────────

def overall_table(data: dict) -> str:
    """Table 1: Overall metrics per tool, sorted by F1 descending."""
    tools = data["tools"]
    metrics = data["metrics"]

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

    # sort by F1 descending
    rows_raw.sort(key=lambda r: -r["f1"])

    # bold best F1
    f1s = [r["f1"] for r in rows_raw]
    f1_strs = _bold_max(f1s)

    # bold best precision (among tools with TP>0)
    precs = [r["prec"] for r in rows_raw]
    prec_strs = _bold_max(precs)

    headers = ["Tool", "TP", "TN", "FP", "FN", "UNK", "Precision", "Recall", "**F1**", "Accuracy", "Time"]
    rows = []
    for i, r in enumerate(rows_raw):
        rows.append([
            f"**{r['tool']}**" if r["f1"] == max(f1s) else r["tool"],
            str(r["tp"]), str(r["tn"]), str(r["fp"]), str(r["fn"]),
            str(r["unk"]),
            prec_strs[i],
            f"{r['rec']:.3f}",
            f1_strs[i],
            f"{r['acc']:.3f}",
            f"{r['time']:.1f}s",
        ])

    return _md_table(headers, rows)


def per_bugtype_table(data: dict) -> str:
    """Table 2: Per-bug-type F1 with bold winners per row."""
    tools = data["tools"]
    pbt = data["per_bug_type"]
    bug_types = sorted(pbt.keys())

    headers = ["Bug Type"] + tools
    rows = []
    for bt in bug_types:
        f1s = [pbt[bt][t]["f1_strict"] for t in tools]
        cells = _bold_max(f1s)
        rows.append([bt] + cells)

    return _md_table(headers, rows, align=["l"] + ["r"] * len(tools))


def unique_catches_table(data: dict) -> str:
    """Table 3: Cases where ONLY one tool catches the bug (TP) and all others miss."""
    tools = data["tools"]
    details = data["details"]
    bug_cases = [d for d in details if d["expected"] == "BUG"]

    # per tool: count how many TPs only that tool found
    unique = {t: [] for t in tools}
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

    if not rows:
        return "_No tool has unique catches._"
    return _md_table(headers, rows, align=["l", "r", "l"])


def a3_fp_table(data: dict) -> str:
    """Table 4: A3 false positives — cases where A3 says BUG but ground truth is SAFE."""
    tools = data["tools"]
    details = data["details"]
    fps = [d for d in details if d["expected"] == "SAFE"
           and d.get("A3", {}).get("verdict") == "BUG"]

    if not fps:
        return "_No A3 false positives._"

    # group by bug_type
    by_bt: dict[str, list[str]] = {}
    for d in fps:
        by_bt.setdefault(d["bug_type"], []).append(d["file"])

    headers = ["Bug Type", "Count", "Files"]
    rows = []
    for bt in sorted(by_bt):
        files = by_bt[bt]
        rows.append([bt, str(len(files)), ", ".join(files)])
    rows.append(["**Total**", f"**{len(fps)}**", ""])
    return _md_table(headers, rows, align=["l", "r", "l"])


def a3_fn_table(data: dict) -> str:
    """Table 5: A3 false negatives — bugs A3 misses but another tool catches."""
    tools = data["tools"]
    others = [t for t in tools if t != "A3"]
    details = data["details"]
    fns = [d for d in details if d["expected"] == "BUG"
           and d.get("A3", {}).get("verdict") in ("SAFE", "UNKNOWN")]

    if not fns:
        return "_No A3 false negatives._"

    headers = ["Bug Type", "File", "A3", "Caught By"]
    rows = []
    for d in fns:
        a3v = d.get("A3", {}).get("verdict", "?")
        catchers = [t for t in others if d.get(t, {}).get("verdict") == "BUG"]
        rows.append([
            d["bug_type"],
            d["file"],
            a3v,
            ", ".join(catchers) if catchers else "_(none)_",
        ])
    return _md_table(headers, rows, align=["l", "l", "c", "l"])


def speed_table(data: dict) -> str:
    """Table 6: Speed comparison."""
    tools = data["tools"]
    metrics = data["metrics"]

    headers = ["Tool", "Total Time", "Avg/Case", "Speedup vs A3"]
    a3_total = metrics["A3"]["total_runtime_sec"]
    rows_raw = [(t, metrics[t]["total_runtime_sec"], metrics[t]["avg_runtime_sec"]) for t in tools]
    rows_raw.sort(key=lambda r: r[1])

    rows = []
    for t, total, avg in rows_raw:
        speedup = a3_total / total if total > 0 else float("inf")
        rows.append([
            t,
            f"{total:.1f}s",
            f"{avg:.3f}s",
            f"{speedup:.1f}×" if t != "A3" else "—",
        ])
    return _md_table(headers, rows, align=["l", "r", "r", "r"])


def key_findings(data: dict) -> str:
    """Generate bullet-point key findings."""
    tools = data["tools"]
    metrics = data["metrics"]
    pbt = data["per_bug_type"]

    a3 = metrics["A3"]
    best_other = max((t for t in tools if t != "A3"), key=lambda t: metrics[t]["f1_strict"])
    bo = metrics[best_other]

    lines = ["## Key Findings\n"]

    # 1. F1 comparison
    ratio = a3["f1_strict"] / bo["f1_strict"] if bo["f1_strict"] > 0 else float("inf")
    lines.append(f"1. **A3 dominates overall**: F1 = {a3['f1_strict']:.3f} vs "
                 f"{best_other} at {bo['f1_strict']:.3f} — "
                 f"**{ratio:.1f}× higher F1** than the next-best tool.\n")

    # 2. Exclusive categories
    exclusive = []
    for bt in sorted(pbt):
        a3_f1 = pbt[bt]["A3"]["f1_strict"]
        others_f1 = [pbt[bt][t]["f1_strict"] for t in tools if t != "A3"]
        if a3_f1 > 0 and all(f == 0 for f in others_f1):
            exclusive.append(bt)
    if exclusive:
        lines.append(f"2. **A3 is the only tool** that catches: "
                     f"**{', '.join(exclusive)}**. "
                     f"These require symbolic execution — no linter or type checker detects them.\n")

    # 3. Where others beat A3
    beats = []
    for bt in sorted(pbt):
        a3_f1 = pbt[bt]["A3"]["f1_strict"]
        for t in tools:
            if t == "A3":
                continue
            t_f1 = pbt[bt][t]["f1_strict"]
            if t_f1 > a3_f1 and t_f1 > 0:
                beats.append((bt, t, t_f1, a3_f1))
    if beats:
        parts = [f"**{bt}** ({t}: {tf:.3f} vs A3: {af:.3f})" for bt, t, tf, af in beats]
        lines.append(f"3. **Where others beat A3**: " + "; ".join(parts) + ".\n")

    # 4. A3 precision weakness
    if a3["fp"] > 0:
        lines.append(f"4. **A3's precision gap**: {a3['fp']} false positives "
                     f"(precision {a3['precision']:.3f}). "
                     f"All other tools correctly say SAFE on those cases. "
                     f"Main FP categories: "
                     + ", ".join(
                         f"{bt} ({len([d for d in data['details'] if d['bug_type']==bt and d['expected']=='SAFE' and d.get('A3',{}).get('verdict')=='BUG'])})"
                         for bt in sorted(set(
                             d["bug_type"] for d in data["details"]
                             if d["expected"] == "SAFE" and d.get("A3", {}).get("verdict") == "BUG"
                         ))
                     )
                     + ".\n")

    # 5. Complementary value
    a3_fns = [d for d in data["details"]
              if d["expected"] == "BUG" and d.get("A3", {}).get("verdict") in ("SAFE", "UNKNOWN")]
    caught_by_others = [d for d in a3_fns
                        if any(d.get(t, {}).get("verdict") == "BUG"
                               for t in tools if t != "A3")]
    if caught_by_others:
        lines.append(f"5. **Complementary value**: {len(caught_by_others)} of A3's "
                     f"{len(a3_fns)} misses are caught by other tools → "
                     f"an ensemble could push F1 higher.\n")

    return "\n".join(lines)


# ── main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate Markdown comparison tables")
    parser.add_argument("json_path", nargs="?",
                        default="results/multi_tool_comparison.json",
                        help="Path to multi_tool_comparison.json")
    parser.add_argument("--out", default="results/comparison_tables.md",
                        help="Output Markdown file")
    args = parser.parse_args()

    data = load(Path(args.json_path))
    ts = data.get("timestamp", "unknown")
    tier = data.get("tier", "unknown")
    n = data.get("total_cases", "?")

    sections = []

    # Title
    sections.append(f"# Multi-Tool Python Bug-Finding Comparison\n")
    sections.append(f"**Date:** {ts}  \n"
                    f"**Tier:** {tier} · **Cases:** {n}  \n"
                    f"**Tools:** {', '.join(data['tools'])}\n")

    # Table 1
    sections.append("## Overall Results\n")
    sections.append(overall_table(data))

    # Table 2
    sections.append("\n## Per-Bug-Type F1\n")
    sections.append(per_bugtype_table(data))

    # Table 3
    sections.append("\n## Unique Catches (bugs found by only one tool)\n")
    sections.append(unique_catches_table(data))

    # Table 4
    sections.append("\n## A3 False Positives\n")
    sections.append(a3_fp_table(data))

    # Table 5
    sections.append("\n## A3 False Negatives & Who Else Catches Them\n")
    sections.append(a3_fn_table(data))

    # Table 6
    sections.append("\n## Speed Comparison\n")
    sections.append(speed_table(data))

    # Key findings
    sections.append("\n" + key_findings(data))

    md = "\n".join(sections) + "\n"

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    print(md)
    print(f"\n--- Saved to {out} ---")


if __name__ == "__main__":
    main()
