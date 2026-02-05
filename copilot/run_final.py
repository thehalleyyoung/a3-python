#!/usr/bin/env python3
"""Final analysis on all repos with guard-based FP reduction."""

from pathlib import Path
from collections import defaultdict
import sys

sys.path.insert(0, str(Path(__file__).parent))

from analyze_with_guards import ImprovedBugAnalyzer

REPOS = {
    'Qlib': ['qlib/backtest', 'qlib/utils'],
    'LightGBM': ['python-package/lightgbm'],
    'DeepSpeed': ['deepspeed/runtime'],
    'FLAML': ['flaml/automl'],
    'GraphRAG': ['graphrag/index'],
    'PromptFlow': ['src/promptflow-core/promptflow'],
    'MSTICPY': ['msticpy/analysis'],
    'Presidio': ['presidio-analyzer/presidio_analyzer'],
    'Guidance': ['guidance/models'],
    'ONNXRuntime': ['onnxruntime/python'],
}

base = Path(__file__).parent / 'external_tools'
all_bugs = defaultdict(int)
repo_bugs = {}
samples = defaultdict(list)
total_files = 0

print('=' * 70)
print('FINAL ANALYSIS: ALL REPOS (WITH GUARD-BASED FP REDUCTION)')
print('=' * 70)

for repo, dirs in REPOS.items():
    repo_path = base / repo
    if not repo_path.exists():
        continue
    
    counts = defaultdict(int)
    for subdir in dirs:
        dir_path = repo_path / subdir
        if not dir_path.exists():
            continue
        py_files = list(dir_path.rglob('*.py'))[:30]
        for pyfile in py_files:
            if 'test' in str(pyfile).lower():
                continue
            analyzer = ImprovedBugAnalyzer(pyfile)
            bugs = analyzer.analyze()
            total_files += 1
            for bug_type, bug_list in bugs.items():
                counts[bug_type] += len(bug_list)
                all_bugs[bug_type] += len(bug_list)
                for bug in bug_list[:2]:
                    if len(samples[bug_type]) < 15:
                        bug['repo'] = repo
                        bug['file'] = str(pyfile.relative_to(repo_path))
                        samples[bug_type].append(bug)
    
    repo_bugs[repo] = dict(counts)
    if sum(counts.values()) > 0:
        print(f'{repo:20} DIV_ZERO:{counts["div_zero"]:3}  NULL_PTR:{counts["null_ptr"]:3}')

print('=' * 70)
print(f'{"TOTAL":20} DIV_ZERO:{all_bugs["div_zero"]:3}  NULL_PTR:{all_bugs["null_ptr"]:3}  BOUNDS:{all_bugs["bounds"]:3}')
print(f'\nFiles analyzed: {total_files}')

print('\n' + '=' * 70)
print('SAMPLE BUGS (for manual FP/FN review)')
print('=' * 70)

for bt in ['div_zero', 'null_ptr']:
    print(f'\n{bt.upper()}:')
    for bug in samples[bt][:8]:
        print(f"  [{bug['repo']}] {bug['file']}:{bug['line']}")
        if 'reason' in bug:
            print(f"    -> {bug['reason']}")
