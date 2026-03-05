#!/usr/bin/env python3
"""Check what findings are near changed lines for BOTH_BUG cases."""
import json, sys, re
from pathlib import Path

data = json.load(open(sys.argv[1]))
A3_ROOT = Path(__file__).resolve().parent.parent
BUGS_DIR = A3_ROOT / "BugsInPy" / "projects"

HUNK_RE = re.compile(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')

MARGIN = 10

for b in data:
    cfg = b['configs']['Full A\u00b3']
    if cfg['classification'] not in ('BOTH_BUG', 'TRUE_POSITIVE', 'FALSE_POSITIVE'):
        continue

    project, bug_id = b['project'], b['bug_id']
    patch_path = BUGS_DIR / project / "bugs" / str(bug_id) / "bug_patch.txt"
    patch_text = patch_path.read_text(errors="replace")

    # Extract changed lines
    changed = {}  # {file: (buggy_set, fixed_set)}
    cur_file = None
    buggy_s, fixed_s = set(), set()
    old_ln = new_ln = 0
    for line in patch_text.splitlines():
        if line.startswith('diff --git'):
            if cur_file:
                changed[cur_file] = (buggy_s, fixed_s)
            cur_file = None
            for p in line.split():
                if p.startswith('b/'):
                    cur_file = p[2:]
                    break
            buggy_s, fixed_s = set(), set()
        m = HUNK_RE.match(line)
        if m:
            old_ln, new_ln = int(m.group(1)), int(m.group(2))
            continue
        if cur_file is None:
            continue
        if line.startswith('---') or line.startswith('+++'):
            continue
        if line.startswith('-'):
            buggy_s.add(old_ln); old_ln += 1
        elif line.startswith('+'):
            fixed_s.add(new_ln); new_ln += 1
        elif line.startswith(' '):
            old_ln += 1; new_ln += 1
    if cur_file:
        changed[cur_file] = (buggy_s, fixed_s)

    print(f"\n{'='*60}")
    print(f"{project}/bug#{bug_id} => {cfg['classification']}")
    for fpath, (bs, fs) in changed.items():
        if not fpath.endswith('.py'):
            continue
        fname = Path(fpath).name
        print(f"  File: {fpath}")
        print(f"    Buggy changed lines: {sorted(bs)[:20]}")
        print(f"    Fixed changed lines: {sorted(fs)[:20]}")

        # Find findings near changed lines
        buggy_near = [f for f in cfg['buggy_findings']
                      if any(abs(f['line'] - cl) <= MARGIN for cl in bs)]
        fixed_near = [f for f in cfg['fixed_findings']
                      if any(abs(f['line'] - cl) <= MARGIN for cl in fs)]
        print(f"    Buggy findings near patch ({len(buggy_near)}):")
        for f in buggy_near:
            print(f"      {f['bug_type']} @ line {f['line']}")
        print(f"    Fixed findings near patch ({len(fixed_near)}):")
        for f in fixed_near:
            print(f"      {f['bug_type']} @ line {f['line']}")
