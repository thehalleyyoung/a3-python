#!/usr/bin/env python3
"""Debug: Check why ValidatedParamsBarrier isn't firing."""
import pickle
from collections import Counter
from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

with open('results/deepspeed_crash_summaries_v2.pkl', 'rb') as f:
    summaries = pickle.load(f)

engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)

# Collect remaining bugs and check their validated_params
remaining = []
for func_name, summary in summaries.items():
    gc = getattr(summary, 'guard_counts', {})
    gb = getattr(summary, 'guarded_bugs', set())
    for bug_type, (guarded_count, total_count) in gc.items():
        if bug_type not in gb and guarded_count == 0:
            is_safe, cert = engine.verify_via_deep_barriers(bug_type, '<v>', summary)
            if not is_safe:
                vp = getattr(summary, 'validated_params', {})
                if vp:
                    remaining.append((func_name, bug_type, vp))

print(f"Remaining with validated_params: {len(remaining)}")
print()

# Collect all validation tags seen
all_tags = Counter()
for func_name, bug_type, vp in remaining:
    for param_idx, tags in vp.items():
        for tag in tags:
            all_tags[tag] += 1

print("All validation tags in remaining bugs:")
for tag, c in all_tags.most_common():
    print(f"  {c:4d}  {tag}")

# Show specific examples where we should match but don't
print("\nExamples with 'nonnull' or 'nonempty' tags still remaining:")
for func_name, bug_type, vp in remaining[:20]:
    for param_idx, tags in vp.items():
        if tags & {'nonnull', 'nonempty', 'exact_length', 'nonzero'}:
            print(f"  {func_name}: {bug_type} — param_{param_idx} has {tags}")
