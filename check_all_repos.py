"""Check all repos for crash bugs."""
from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer
from pathlib import Path
from collections import Counter
import sys

# Crash bug types to check
CRASH_TYPES = {'DIV_ZERO', 'NULL_PTR', 'BOUNDS', 'ASSERT_FAIL', 'TYPE_CONFUSION', 
               'INTEGER_OVERFLOW', 'RECURSION_DEPTH', 'ITERATOR_INVALID'}

# Just check one repo at a time
repo = sys.argv[1] if len(sys.argv) > 1 else 'Counterfit'

base = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools')
path = base / repo

if not path.exists():
    print(f"{repo}: Not found")
    sys.exit(1)

print(f"Analyzing {repo}...")
cg = build_call_graph_from_directory(path)
print(f"  Functions: {len(cg.functions)}")

computer = BytecodeCrashSummaryComputer(cg)
summaries = computer.compute_all()
print(f"  Summaries: {len(summaries)}")

# Count all unguarded crash bugs by type
crash_counts = Counter()
crash_examples = {}

for name, summ in summaries.items():
    for bug_type in summ.may_trigger:
        if bug_type in CRASH_TYPES and bug_type not in summ.guarded_bugs:
            crash_counts[bug_type] += 1
            if bug_type not in crash_examples:
                crash_examples[bug_type] = []
            if len(crash_examples[bug_type]) < 3:
                crash_examples[bug_type].append(name)

print(f"\n{repo} - Unguarded crash bugs:")
for bug_type, count in crash_counts.most_common():
    print(f"\n  {bug_type}: {count}")
    for ex in crash_examples.get(bug_type, []):
        print(f"    {ex}")
