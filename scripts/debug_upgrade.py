#!/usr/bin/env python3
"""Debug script to see what proofs are produced for b02 case."""
import tempfile, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a3_python.analyzer import Analyzer

code = """\
nums = [2, 4, 6, 8, 10, 12, 14, 16]
found = 0
for n in nums:
    if n == 99:
        found = 1
    elif n > 10:
        pass
    elif n > 5:
        pass
    else:
        pass
result = 100 / found  # BUG: found = 0, 99 not in list
"""

with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
    f.write(code)
    path = f.name

try:
    from pathlib import Path as P
    path = P(path)
    a = Analyzer(verbose=True, max_paths=100, max_depth=300)
    r = a.analyze_file_kitchensink(path)
    print()
    print("=" * 60)
    print("FINAL RESULT")
    print("=" * 60)
    print(f"VERDICT: {r.verdict}")
    print(f"BUG_TYPE: {r.bug_type}")
    print(f"MESSAGE: {r.message[:400] if r.message else ''}")
    print(f"PATHS: {r.paths_explored}")
    if r.per_bug_type:
        print(f"PER_BUG_TYPE keys: {list(r.per_bug_type.keys())}")
        for k, v in r.per_bug_type.items():
            if isinstance(v, dict):
                print(f"  {k}:")
                for kk, vv in v.items():
                    s = str(vv)
                    if len(s) > 200:
                        s = s[:200] + "..."
                    print(f"    {kk}: {s}")
            else:
                print(f"  {k}: {v}")
    else:
        print("PER_BUG_TYPE: None")
finally:
    os.unlink(path)
