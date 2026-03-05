#!/usr/bin/env python3
"""Quick analysis of ablation JSON results."""
import json, sys
from pathlib import Path
from collections import Counter

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results/ablation_full.json")
data = json.load(open(path))
print(f"Total bugs evaluated: {len(data)}")
print()

# Get config names from first entry
configs = list(data[0]["configs"].keys())

# Classification breakdown per config
print("=== Classification Breakdown ===")
for cfg in configs:
    classes = Counter()
    for bug in data:
        c = bug["configs"].get(cfg, {})
        cls = c.get("classification", "MISSING")
        classes[cls] += 1
    print(f"  {cfg}:")
    for cls in ["TRUE_POSITIVE", "FALSE_NEGATIVE", "FALSE_POSITIVE", "BOTH_BUG", "NO_PATCH", "ERROR"]:
        if classes[cls]:
            print(f"    {cls}: {classes[cls]}")

print()
print("=== TRUE_POSITIVE bugs (found in buggy, not in fixed) ===")
for bug in data:
    c = bug["configs"].get(configs[0], {})
    if c.get("classification") == "TRUE_POSITIVE":
        print(f"  {bug['project']}/bug#{bug['bug_id']}")
        # Check if all configs agree
        others = [bug["configs"][cfg]["classification"] for cfg in configs[1:]]
        if any(o != "TRUE_POSITIVE" for o in others):
            for cfg in configs[1:]:
                print(f"    {cfg}: {bug['configs'][cfg]['classification']}")

print()
print("=== FALSE_POSITIVE bugs (found in fixed too) ===")
for bug in data:
    c = bug["configs"].get(configs[0], {})
    if c.get("classification") == "FALSE_POSITIVE":
        print(f"  {bug['project']}/bug#{bug['bug_id']}")

print()
print("=== BOTH_BUG cases (findings in both buggy AND fixed) ===")
for bug in data:
    c = bug["configs"].get(configs[0], {})
    if c.get("classification") == "BOTH_BUG":
        print(f"  {bug['project']}/bug#{bug['bug_id']}")
        # Show what was found
        cfg_data = bug["configs"][configs[0]]
        buggy_types = set(f["bug_type"] for f in cfg_data.get("buggy_findings", []))
        fixed_types = set(f["bug_type"] for f in cfg_data.get("fixed_findings", []))
        print(f"    buggy findings: {buggy_types or 'none listed'}")
        print(f"    fixed findings: {fixed_types or 'none listed'}")

print()
print("=== Disagreements Between Configs ===")
disagree = 0
for bug in data:
    classes = set()
    for cfg in configs:
        c = bug["configs"].get(cfg, {})
        classes.add(c.get("classification", "MISSING"))
    if len(classes) > 1:
        disagree += 1
        print(f"  {bug['project']}/bug#{bug['bug_id']}:")
        for cfg in configs:
            print(f"    {cfg}: {bug['configs'][cfg]['classification']}")
print(f"Total disagreements: {disagree} out of {len(data)}")

print()
print("=== Timing Summary ===")
for cfg in configs:
    times = [bug["configs"][cfg]["total_time"] for bug in data if cfg in bug["configs"]]
    times.sort()
    total = sum(times)
    mean = total / len(times)
    median = times[len(times) // 2]
    p95 = times[int(len(times) * 0.95)]
    mx = max(times)
    print(f"  {cfg}:")
    print(f"    total={total:.1f}s  mean={mean:.2f}s  median={median:.2f}s  p95={p95:.1f}s  max={mx:.1f}s")

print()
print("=== Per-Project Summary (Full config) ===")
projects = sorted(set(b["project"] for b in data))
for proj in projects:
    proj_bugs = [b for b in data if b["project"] == proj]
    tp = sum(1 for b in proj_bugs if b["configs"][configs[0]]["classification"] == "TRUE_POSITIVE")
    fn = sum(1 for b in proj_bugs if b["configs"][configs[0]]["classification"] == "FALSE_NEGATIVE")
    fp = sum(1 for b in proj_bugs if b["configs"][configs[0]]["classification"] == "FALSE_POSITIVE")
    both = sum(1 for b in proj_bugs if b["configs"][configs[0]]["classification"] == "BOTH_BUG")
    det_rate = tp / max(tp + fn + both, 1) * 100
    print(f"  {proj:15s}: {len(proj_bugs):3d} bugs  TP={tp} FN={fn} FP={fp} BOTH={both}  det={det_rate:.1f}%")
