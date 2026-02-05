#!/usr/bin/env python3
"""
Diagnose why Bayesian scorer is catching 92% of bugs with 87% confidence.
"""
import sys
from pathlib import Path
import pickle
from collections import Counter

from pyfromscratch.barriers.bayesian_fp_scorer import BayesianConfidenceScorer

# Load the cached summaries
cache_file = Path('results/deepspeed_crash_summaries.pkl')
if not cache_file.exists():
    print(f"ERROR: {cache_file} not found")
    sys.exit(1)

print("Loading summaries...")
with open(cache_file, 'rb') as f:
    crash_summaries = pickle.load(f)

print(f"Loaded {len(crash_summaries)} summaries")
print()

# Test Bayesian scorer on some examples
scorer = BayesianConfidenceScorer()

print("="*80)
print("TESTING BAYESIAN SCORER ON SAMPLE BUGS")
print("="*80)
print()

# Collect stats
confidence_counts = Counter()
signal_counts = Counter()
examples_by_signal_count = {0: [], 1: [], 2: [], 3: []}

sample_count = 0
for func_name, summary in list(crash_summaries.items())[:500]:
    # Check for common bug types
    for bug_type in ['NULL_PTR', 'DIV_ZERO', 'BOUNDS', 'VALUE_ERROR']:
        bug_vars = ['param_0', 'param_1', 'result', 'index', 'value', None]
        
        for bug_var in bug_vars:
            is_fp, confidence, signals = scorer.is_likely_false_positive(
                bug_type, bug_var or '', summary, threshold=0.85
            )
            
            if sample_count < 20:
                print(f"Example {sample_count + 1}:")
                print(f"  Function: {func_name}")
                print(f"  Bug: {bug_type} on {bug_var}")
                print(f"  Is FP: {is_fp} (confidence={confidence:.1%})")
                print(f"  Signals: {len(signals)}")
                for sig in signals:
                    print(f"    - {sig.name}: LR={sig.likelihood_ratio():.2f}")
                print()
                sample_count += 1
            
            # Track stats
            conf_bucket = int(confidence * 10) * 10  # Bucket to nearest 10%
            confidence_counts[conf_bucket] += 1
            signal_counts[len(signals)] += 1
            
            if len(signals) in examples_by_signal_count:
                if len(examples_by_signal_count[len(signals)]) < 3:
                    examples_by_signal_count[len(signals)].append(
                        (func_name, bug_type, bug_var, confidence, signals)
                    )

print("="*80)
print("STATISTICS")
print("="*80)
print()

print("Confidence distribution:")
for conf_bucket in sorted(confidence_counts.keys()):
    count = confidence_counts[conf_bucket]
    pct = count / sum(confidence_counts.values()) * 100
    bar = '█' * int(pct / 2)
    print(f"  {conf_bucket:3d}%: {count:5d} ({pct:5.1f}%) {bar}")

print()
print("Signal count distribution:")
for sig_count in sorted(signal_counts.keys()):
    count = signal_counts[sig_count]
    pct = count / sum(signal_counts.values()) * 100
    bar = '█' * int(pct / 2)
    print(f"  {sig_count} signals: {count:5d} ({pct:5.1f}%) {bar}")

print()
print("="*80)
print("EXAMPLES BY SIGNAL COUNT")
print("="*80)
print()

for sig_count in [0, 1, 2, 3]:
    if sig_count in examples_by_signal_count and examples_by_signal_count[sig_count]:
        print(f"Examples with {sig_count} signals:")
        for func, bug, var, conf, sigs in examples_by_signal_count[sig_count]:
            print(f"  - {bug} on {var} in {func}: conf={conf:.1%}")
            for sig in sigs:
                print(f"      {sig.name}: LR={sig.likelihood_ratio():.2f}")
        print()

print("="*80)
print("DIAGNOSIS")
print("="*80)
print()

# Check if prior is the issue
zero_signal_confidence = scorer.prior_fp_rate
print(f"Prior FP rate (used when 0 signals): {zero_signal_confidence:.1%}")
print()

if zero_signal_confidence > 0.80:
    print("⚠️  PROBLEM FOUND:")
    print(f"   The prior FP rate is {zero_signal_confidence:.1%}, which is above")
    print("   the 85% threshold for marking as FP.")
    print()
    print("   This means ANY bug with 0 signals is automatically marked as FP!")
    print()
    print("   This is unsound - bugs with no evidence should NOT be assumed safe.")
    print()
    print("   RECOMMENDATION:")
    print("   - Lower prior_fp_rate to ~0.40 (40% of bugs are FPs)")
    print("   - Only mark as FP when we have POSITIVE evidence (signals)")
    print("   - Require at least 1-2 signals before classifying as FP")
else:
    print("✓ Prior FP rate looks reasonable")
