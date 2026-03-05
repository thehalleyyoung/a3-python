#!/usr/bin/env python3
"""Check how many extracted BugsInPy fragments are valid Python."""
import json, os, sys, textwrap
from pathlib import Path

A3_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(A3_ROOT / "scripts"))
from ablation_study import _parse_patch, list_bugs, BUGS_DIR, _load_in_scope_set

in_scope = _load_in_scope_set()
ALL_PROJECTS = sorted(d.name for d in BUGS_DIR.iterdir() if d.is_dir()) if BUGS_DIR.exists() else []

valid = 0
invalid = 0
no_patch = 0
tp_bugs = {"PySnooper/1", "PySnooper/2", "cookiecutter/1", "keras/44", "pandas/125", "scrapy/8"}

for project in ALL_PROJECTS:
    for bug_id in list_bugs(project):
        if (project, bug_id) not in in_scope:
            continue
        patch_path = BUGS_DIR / project / "bugs" / str(bug_id) / "bug_patch.txt"
        if not patch_path.exists():
            no_patch += 1
            continue
        versions = _parse_patch(patch_path.read_text(errors="replace"))
        if not versions:
            no_patch += 1
            continue

        is_tp = f"{project}/{bug_id}" in tp_bugs
        all_valid = True
        for fname, (buggy, fixed) in versions.items():
            for label, src in [("buggy", buggy), ("fixed", fixed)]:
                try:
                    compile(src, fname, "exec")
                except SyntaxError:
                    all_valid = False
                    # Also try dedented
                    dedented = textwrap.dedent(src)
                    try:
                        compile(dedented, fname, "exec")
                        dedent_ok = True
                    except SyntaxError:
                        dedent_ok = False

                    if is_tp or (invalid < 5 and not is_tp):
                        lines = src.count('\n') + 1
                        print(f"  {'[TP] ' if is_tp else ''}{project}/bug#{bug_id} {fname} ({label}): "
                              f"{lines} lines, dedent={'OK' if dedent_ok else 'FAIL'}")
                        print(f"    First 100 chars: {src[:100]!r}")

        if all_valid:
            valid += 1
        else:
            invalid += 1

print(f"\nSummary of 250 in-scope bugs:")
print(f"  Valid Python fragments:   {valid}")
print(f"  Invalid Python fragments: {invalid}")
print(f"  No patch/no files:        {no_patch}")
