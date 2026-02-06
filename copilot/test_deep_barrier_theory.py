#!/usr/bin/env python3
"""
Test deep barrier theory on 329 unguarded DeepSpeed bugs.
Measure how many false positives we can eliminate.
"""

import pickle
import logging
from pathlib import Path
from collections import Counter
from pyfromscratch.barriers.deep_barrier_theory import (
    DeepBarrierTheoryEngine,
    BarrierType
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Load crash summaries
cache_file = Path('results/deepspeed_crash_summaries.pkl')
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)

# Collect unguarded bugs
unguarded_bugs = []

for func_name, summary in summaries.items():
    if hasattr(summary, 'guarded_bugs') and summary.guarded_bugs:
        for bug_type in summary.guarded_bugs:
            guard_count = (0, 0)
            if hasattr(summary, 'guard_counts') and bug_type in summary.guard_counts:
                guard_count = summary.guard_counts[bug_type]
            
            if guard_count[0] == 0:  # Unguarded
                unguarded_bugs.append({
                    'function': func_name,
                    'bug_type': bug_type,
                    'summary': summary,
                    'total_count': guard_count[1]
                })

print("=" * 80)
print("DEEP BARRIER THEORY: TESTING ON DEEPSPEED UNGUARDED BUGS")
print("=" * 80)
print()
print(f"Total unguarded bugs to analyze: {len(unguarded_bugs)}")
print()

# Initialize engine
engine = DeepBarrierTheoryEngine()

# Statistics
proven_safe = []
still_unsafe = []
barrier_counts = Counter()

# Analyze each bug (sample first, then all if successful)
print("Analyzing sample of 50 bugs...")
print()

sample_bugs = unguarded_bugs[:50]

for i, bug in enumerate(sample_bugs, 1):
    func_name = bug['function']
    bug_type = bug['bug_type']
    summary = bug['summary']
    
    # Short function name for display
    short_name = func_name.split('.')[-1] if '.' in func_name else func_name
    
    # Verify with deep barriers
    is_safe, cert = engine.verify_via_deep_barriers(
        bug_type,
        '<variable>',  # We don't always have the variable name
        summary
    )
    
    if is_safe and cert:
        proven_safe.append(bug)
        barrier_counts[cert.barrier_type] += 1
        logger.info(
            f"[{i}/{len(sample_bugs)}] ✓ {short_name}: "
            f"{cert.barrier_type.value} (conf={cert.confidence:.0%})"
        )
    else:
        still_unsafe.append(bug)
        logger.info(f"[{i}/{len(sample_bugs)}] ✗ {short_name}: TRUE BUG")

print()
print("=" * 80)
print("RESULTS")
print("=" * 80)
print()

print(f"Total analyzed: {len(sample_bugs)}")
print(f"Proven safe (FPs): {len(proven_safe)} ({len(proven_safe)/len(sample_bugs)*100:.1f}%)")
print(f"Still unsafe (likely true bugs): {len(still_unsafe)} ({len(still_unsafe)/len(sample_bugs)*100:.1f}%)")
print()

print("Barrier effectiveness:")
print("-" * 40)
for barrier_type, count in barrier_counts.most_common():
    pct = count / len(sample_bugs) * 100
    print(f"  {barrier_type.value:30s}: {count:3d} bugs ({pct:5.1f}%)")

print()
print("=" * 80)
print("EXTRAPOLATION TO ALL 329 BUGS")
print("=" * 80)
print()

# Extrapolate to all bugs
fp_rate = len(proven_safe) / len(sample_bugs)
estimated_fps = int(329 * fp_rate)
estimated_true_bugs = 329 - estimated_fps

print(f"Sample FP rate: {fp_rate*100:.1f}%")
print()
print(f"Estimated breakdown of 329 unguarded bugs:")
print(f"  - False positives (safe via barriers): ~{estimated_fps} bugs")
print(f"  - True bugs requiring manual review: ~{estimated_true_bugs} bugs")
print()

if fp_rate >= 0.70:
    print("✓ ACHIEVED TARGET: 70-90% FP reduction")
    print()
    print("Deep barrier theory successfully eliminates most false positives!")
elif fp_rate >= 0.40:
    print("⚠ PARTIAL SUCCESS: 40-70% FP reduction")
    print()
    print("Deep barriers help but could be improved further.")
else:
    print("✗ BELOW TARGET: <40% FP reduction")
    print()
    print("Deep barriers need more work or bugs are genuinely unsafe.")

print()
print("Top barrier types for improvement:")
for barrier_type, count in barrier_counts.most_common(3):
    print(f"  - {barrier_type.value}: {count} bugs proven safe")

print()
print(f"Results saved to: results/deep_barrier_results.txt")

# Save detailed results
with open('results/deep_barrier_results.txt', 'w') as f:
    f.write("DEEP BARRIER THEORY RESULTS\n")
    f.write("=" * 80 + "\n\n")
    f.write(f"Sample size: {len(sample_bugs)} bugs\n")
    f.write(f"Proven safe: {len(proven_safe)} ({len(proven_safe)/len(sample_bugs)*100:.1f}%)\n")
    f.write(f"Still unsafe: {len(still_unsafe)} ({len(still_unsafe)/len(sample_bugs)*100:.1f}%)\n\n")
    
    f.write("Barrier effectiveness:\n")
    f.write("-" * 40 + "\n")
    for barrier_type, count in barrier_counts.most_common():
        pct = count / len(sample_bugs) * 100
        f.write(f"  {barrier_type.value:30s}: {count:3d} bugs ({pct:5.1f}%)\n")
    f.write("\n")
    
    f.write("Extrapolation to all 329 bugs:\n")
    f.write("-" * 40 + "\n")
    f.write(f"  Estimated FPs: {estimated_fps}\n")
    f.write(f"  Estimated true bugs: {estimated_true_bugs}\n\n")
    
    f.write("Sample bugs proven safe:\n")
    f.write("-" * 40 + "\n")
    for bug in proven_safe[:20]:
        f.write(f"  {bug['function']}\n")
        f.write(f"    Type: {bug['bug_type']}\n")
