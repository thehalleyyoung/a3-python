#!/usr/bin/env python
"""Scan PyTorch for bugs."""

from pyfromscratch.analyzer import Analyzer
from pathlib import Path
import json

# Create analyzer with reasonable limits
analyzer = Analyzer(max_paths=500, max_depth=500, timeout_ms=5000)

# Focus on utility modules, nn implementations, optimizers
target_dirs = [
    'torch/nn/utils',
    'torch/optim',
    'torch/utils/data',
    'torch/distributed/utils',
    'torch/fx',
]

pytorch_root = Path('results/public_repos/pytorch')
all_results = []
scanned = 0

for target_dir in target_dirs:
    dir_path = pytorch_root / target_dir
    if dir_path.exists():
        py_files = list(dir_path.rglob('*.py'))[:25]  # Limit to 25 per dir
        for f in py_files:
            print(f'Scanning: {f.relative_to(pytorch_root)}')
            scanned += 1
            try:
                result = analyzer.analyze_file(f)
                if result.verdict == 'BUG':
                    print(f'  -> BUG: {result.bug_type}')
                    all_results.append({
                        'file': str(f.relative_to(pytorch_root)),
                        'verdict': result.verdict,
                        'bug_type': result.bug_type,
                        'details': str(result.counterexample)[:500] if result.counterexample else None
                    })
            except Exception as e:
                print(f'  ERROR: {e}')

print(f'\n\nScanned {scanned} files')
print(f'Total bugs found: {len(all_results)}')
print(json.dumps(all_results, indent=2))

# Save results
with open('results/pytorch_scan_results.json', 'w') as f:
    json.dump(all_results, f, indent=2)
