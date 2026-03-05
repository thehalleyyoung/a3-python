#!/usr/bin/env python3
"""Diagnose why FN rate is so high in ablation study."""
import os, sys, re, tempfile, subprocess
from pathlib import Path

A3_ROOT = Path(__file__).resolve().parent.parent
BUGS_DIR = A3_ROOT / "BugsInPy" / "projects"

# ── Test 1: Show what _parse_patch produces ──

def parse_patch_current(patch_text):
    """Current implementation from ablation_study.py"""
    file_diffs = {}
    current_file = None
    for line in patch_text.splitlines(keepends=True):
        if line.startswith("diff --git"):
            parts = line.split()
            for p in parts:
                if p.startswith("b/"):
                    current_file = p[2:].strip()
                    break
            else:
                current_file = None
            if current_file:
                file_diffs.setdefault(current_file, [])
        elif current_file is not None:
            file_diffs[current_file].append(line)

    result = {}
    for fname, diff_lines in file_diffs.items():
        if not fname.endswith(".py"):
            continue
        base = os.path.basename(fname)
        if base.startswith("test_") or base.startswith("tests_"):
            continue
        if "/test/" in fname or "/tests/" in fname:
            continue

        buggy_lines = []
        fixed_lines = []
        in_hunk = False
        for dl in diff_lines:
            if dl.startswith("@@"):
                in_hunk = True
                continue
            if dl.startswith("---") or dl.startswith("+++"):
                continue
            if dl.startswith("diff --git"):
                in_hunk = False
                continue
            if not in_hunk:
                continue

            if dl.startswith("-"):
                buggy_lines.append(dl[1:])
            elif dl.startswith("+"):
                fixed_lines.append(dl[1:])
            else:
                content = dl[1:] if dl.startswith(" ") else dl
                buggy_lines.append(content)
                fixed_lines.append(content)

        buggy_src = "".join(buggy_lines)
        fixed_src = "".join(fixed_lines)
        if buggy_src.strip() or fixed_src.strip():
            result[fname] = (buggy_src, fixed_src)

    return result


# Test on ansible/bug#1
print("=" * 70)
print("TEST 1: What does _parse_patch produce?")
print("=" * 70)

patch = open(BUGS_DIR / "ansible" / "bugs" / "1" / "bug_patch.txt").read()
versions = parse_patch_current(patch)

for fname, (buggy, fixed) in versions.items():
    print(f"\nFile: {fname}")
    print(f"  Buggy lines: {buggy.count(chr(10))+1}")
    print(f"  Fixed lines: {fixed.count(chr(10))+1}")
    print(f"  Buggy starts with: {buggy[:200]!r}")
    print(f"  Can it parse?")
    try:
        compile(buggy, fname, "exec")
        print("    YES - valid Python")
    except SyntaxError as e:
        print(f"    NO  - {e}")


# ── Test 2: Run A3 on the extracted fragment ──
print()
print("=" * 70)
print("TEST 2: What does A3 return on these fragments?")
print("=" * 70)

for fname, (buggy, fixed) in versions.items():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(buggy)
        tmp = f.name
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "a3_python", tmp,
             "--functions", "--deduplicate", "--min-confidence", "0.5"],
            capture_output=True, text=True, timeout=30,
            cwd=str(A3_ROOT),
        )
        print(f"\nFile: {fname} (buggy)")
        print(f"  Exit code: {proc.returncode}")
        print(f"  Stdout ({len(proc.stdout)} chars): {proc.stdout[:500]}")
        print(f"  Stderr ({len(proc.stderr)} chars): {proc.stderr[:500]}")
    finally:
        os.unlink(tmp)


# ── Test 3: Check how bugsinpy_eval.py does it ──
print()
print("=" * 70)
print("TEST 3: Does BugsInPy have full source files?")
print("=" * 70)

# Check if there are project_sources or similar
bug_dir = BUGS_DIR / "ansible" / "bugs" / "1"
print(f"Contents of {bug_dir}:")
for item in sorted(bug_dir.iterdir()):
    print(f"  {item.name} {'(dir)' if item.is_dir() else f'({item.stat().st_size} bytes)'}")


# ── Test 4: How does bugsinpy_eval.py get full files? ──
print()
print("=" * 70)
print("TEST 4: How does the existing evaluator (bugsinpy_eval.py) work?")
print("=" * 70)
eval_script = A3_ROOT / "scripts" / "bugsinpy_eval.py"
if eval_script.exists():
    text = eval_script.read_text()
    # Find the evaluate_bug or run_a3 functions
    for pattern in ["def evaluate", "def run_a3", "def extract", "def reconstruct", "git checkout", "git diff", "git show"]:
        lines = [f"  L{i+1}: {line.rstrip()}" for i, line in enumerate(text.splitlines()) if pattern in line.lower()]
        if lines:
            print(f"\n  Matches for '{pattern}':")
            for l in lines[:5]:
                print(f"    {l}")
else:
    print("  bugsinpy_eval.py not found")
