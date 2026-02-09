#!/usr/bin/env python3
"""Extract TPs from analysis log, grouped by repo."""
import re, json

lines = open("results/analysis_log.txt").readlines()
current_repo = None
repo_tps = {}

for line in lines:
    m = re.match(r"\s+ANALYZING:\s+(\S+)", line)
    if m:
        current_repo = m.group(1)
        repo_tps[current_repo] = []
    stripped = line.strip()
    if "\u26a0\ufe0f" in stripped:
        m2 = re.search(r"\u26a0\ufe0f\s+(\S+)\s+in\s+(.+)", stripped)
        if m2 and current_repo:
            repo_tps[current_repo].append({"bug_type": m2.group(1), "func": m2.group(2).strip(), "is_test": False})
    elif "(test)" in stripped and " in " in stripped:
        m2 = re.search(r"\(test\)\s+(\S+)\s+in\s+(.+)", stripped)
        if m2 and current_repo:
            repo_tps[current_repo].append({"bug_type": m2.group(1), "func": m2.group(2).strip(), "is_test": True})

for repo, tps in repo_tps.items():
    if tps:
        print(f"{repo}: {len(tps)} TPs")
        for tp in tps:
            marker = "(test) " if tp["is_test"] else ""
            print(f"  {marker}{tp['bug_type']:20s} {tp['func']}")

out = {repo: tps for repo, tps in repo_tps.items() if tps}
with open("results/tps_by_repo.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\nSaved to results/tps_by_repo.json")
