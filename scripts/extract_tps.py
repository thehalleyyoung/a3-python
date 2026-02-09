#!/usr/bin/env python3
"""Extract all TPs from the analysis log, organized by repo."""
import re, json

with open("results/analysis_log.txt") as f:
    text = f.read()

# Split by ANALYZING sections
sections = re.split(r'={70}\n\s+ANALYZING:\s+(\w+)', text)

repos = {}
for i in range(1, len(sections), 2):
    repo = sections[i]
    content = sections[i+1] if i+1 < len(sections) else ''
    tps = []
    for line in content.split('\n'):
        line = line.strip()
        if '⚠️' in line or line.startswith('(test)'):
            m = re.match(r'(?:⚠️\s*|⚠️\s*|\(test\)\s+)(\S+)\s+in\s+(.+)', line)
            if m:
                tps.append({"bug_type": m.group(1), "func": m.group(2).strip(), "is_test": "(test)" in line})
    if tps:
        repos[repo] = tps

for repo, tps in repos.items():
    print(f"{repo}: {len(tps)} TPs")

# Save as JSON for further processing
with open("/tmp/all_tps_by_repo.json", "w") as f:
    json.dump(repos, f, indent=2)

print(f"\nTotal: {sum(len(v) for v in repos.values())} TPs across {len(repos)} repos")
print("Saved to /tmp/all_tps_by_repo.json")
