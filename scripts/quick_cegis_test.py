#!/usr/bin/env python3
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import analyze

# Test on first 3 files
with open('results/tier1_safe_files_for_cegis.json') as f:
    safe_files = json.load(f)

print(f'Testing CEGIS synthesis on 3 sample SAFE files')
print('=' * 80)

results = []
proof_count = 0

for i, item in enumerate(safe_files[:3], 1):
    file_path = Path(item['file'])
    bug_type = item['bug_type']
    repo = item['repo']
    
    print(f'\n[{i}/3] {repo} / {file_path.name}')
    
    start = time.time()
    try:
        result = analyze(file_path, verbose=False)
        elapsed = time.time() - start
        
        if result.verdict == 'SAFE' and result.barrier:
            proof_count += 1
            templates = result.synthesis_result.templates_tried if result.synthesis_result else 0
            print(f'  ✓ PROOF: {result.barrier.name} ({templates} templates, {elapsed:.2f}s)')
        else:
            print(f'  ○ {result.verdict} without proof ({elapsed:.2f}s)')
    except Exception as e:
        print(f'  ✗ ERROR: {e}')

print(f'\n{proof_count}/3 files got proofs')
