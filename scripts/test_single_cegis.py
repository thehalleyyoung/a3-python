#!/usr/bin/env python3
"""Quick test: apply analyzer to one SAFE file and check if barrier synthesis runs."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import analyze

# Test on one of the SAFE files
test_file = Path("results/public_repos/clones/click/src/click/globals.py")

if not test_file.exists():
    print(f"Error: {test_file} not found")
    sys.exit(1)

print(f"Testing CEGIS synthesis on: {test_file}")
print("=" * 80)

result = analyze(test_file, verbose=True)

print("\n" + "=" * 80)
print(f"Verdict: {result.verdict}")
print(f"Paths explored: {result.paths_explored}")

if result.barrier:
    print(f"✓ Barrier certificate found: {result.barrier.name}")
    if result.synthesis_result:
        print(f"  Templates tried: {result.synthesis_result.templates_tried}")
        print(f"  Synthesis time: {result.synthesis_result.synthesis_time_ms:.1f}ms")
else:
    print("✗ No barrier certificate (SAFE without proof or not SAFE)")

if result.synthesis_result:
    print(f"\nSynthesis status: {'SUCCESS' if result.synthesis_result.success else 'FAILED'}")
    print(result.synthesis_result.summary())

print("\n" + result.summary())
