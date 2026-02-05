#!/usr/bin/env python3
"""
Examine high-confidence bugs to identify false positive patterns and improve filtering.
"""

import json
from pathlib import Path
from collections import defaultdict
import re

RESULTS_FILE = Path(__file__).parent / 'results' / 'deepspeed_nonsecurity_analysis.json'
DEEPSPEED_PATH = Path(__file__).parent / 'external_tools' / 'DeepSpeed'

def load_results():
    """Load analysis results."""
    with open(RESULTS_FILE) as f:
        return json.load(f)

def examine_bug_context(bug):
    """Load source code around bug location to understand context."""
    try:
        file_path = Path(bug['full_path'])
        if not file_path.exists():
            return None
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Get context around bug location (±5 lines)
        start = max(0, bug['line'] - 5)
        end = min(len(lines), bug['line'] + 5)
        
        return {
            'before': lines[start:bug['line']-1],
            'bug_line': lines[bug['line']-1] if bug['line'] <= len(lines) else '',
            'after': lines[bug['line']:end],
            'function_context': lines[max(0, bug['line']-10):min(len(lines), bug['line']+3)]
        }
    except:
        return None

def identify_false_positive_patterns(bugs_sample):
    """Identify common false positive patterns."""
    
    patterns = {
        'test_files': 0,
        'benchmark_files': 0,
        'example_files': 0,
        'setup_config': 0,
        'list_comprehension': 0,
        'iterator_patterns': 0,
        'loop_with_known_bounds': 0,
        'string_operations': 0,
        'duplicate_reports': 0,
        'other': 0
    }
    
    fp_examples = defaultdict(list)
    seen = set()
    
    for bug in bugs_sample:
        # Create unique key
        key = (bug['file'], bug['function'], bug['line'], bug['type'])
        if key in seen:
            patterns['duplicate_reports'] += 1
            continue
        seen.add(key)
        
        file_lower = bug['file'].lower()
        func_lower = bug['function'].lower()
        
        # Test files
        if 'test' in file_lower or 'test' in func_lower:
            patterns['test_files'] += 1
            fp_examples['test_files'].append(bug)
            continue
        
        # Benchmark/perf files
        if any(x in file_lower for x in ['bench', 'perf', 'speed', 'profile']):
            patterns['benchmark_files'] += 1
            fp_examples['benchmark_files'].append(bug)
            continue
        
        # Example/demo files
        if any(x in file_lower for x in ['example', 'demo', 'sample', 'tutorial']):
            patterns['example_files'] += 1
            fp_examples['example_files'].append(bug)
            continue
        
        # Setup/config files
        if any(x in file_lower for x in ['setup.py', 'config', 'install']):
            patterns['setup_config'] += 1
            fp_examples['setup_config'].append(bug)
            continue
        
        # Get context
        context = examine_bug_context(bug)
        if context and context['bug_line']:
            line = context['bug_line'].strip()
            
            # List comprehensions often safe
            if '[' in line and 'for' in line and ']' in line:
                patterns['list_comprehension'] += 1
                fp_examples['list_comprehension'].append(bug)
                continue
            
            # Iterator patterns (enumerate, zip, etc.)
            if any(x in line for x in ['enumerate(', 'zip(', 'iter(']):
                patterns['iterator_patterns'] += 1
                fp_examples['iterator_patterns'].append(bug)
                continue
            
            # String operations
            if bug['type'] == 'BOUNDS' and any(x in line for x in ['.split(', '.partition(', 'str[', "'"]):
                patterns['string_operations'] += 1
                fp_examples['string_operations'].append(bug)
                continue
        
        patterns['other'] += 1
    
    return patterns, fp_examples

def analyze_high_confidence_bugs():
    """Analyze high-confidence bugs to identify patterns."""
    
    print("="*80)
    print("ANALYZING HIGH-CONFIDENCE BUGS FOR FALSE POSITIVE PATTERNS")
    print("="*80)
    print()
    
    data = load_results()
    high_conf = data['high_confidence_findings']
    
    print(f"Total high-confidence bugs: {len(high_conf)}")
    print(f"Analyzing sample of {min(200, len(high_conf))} bugs...\n")
    
    # Sample bugs
    sample_size = min(200, len(high_conf))
    sample = high_conf[:sample_size]
    
    # Identify patterns
    patterns, examples = identify_false_positive_patterns(sample)
    
    print("="*80)
    print("FALSE POSITIVE PATTERNS IDENTIFIED")
    print("="*80)
    print()
    
    total_fps = sum(patterns.values()) - patterns['other']
    print(f"Likely False Positives: {total_fps}/{sample_size} ({100*total_fps/sample_size:.1f}%)")
    print()
    
    for pattern, count in sorted(patterns.items(), key=lambda x: -x[1]):
        if count > 0:
            pct = 100 * count / sample_size
            print(f"  {pattern:25s}: {count:3d} ({pct:5.1f}%)")
    
    print()
    print("="*80)
    print("EXAMPLE FALSE POSITIVES")
    print("="*80)
    print()
    
    for pattern, bug_list in examples.items():
        if bug_list:
            print(f"\n{pattern.upper()}:")
            for bug in bug_list[:3]:  # Show first 3 examples
                print(f"  • {bug['file']}:{bug['function']}() line {bug['line']}")
                context = examine_bug_context(bug)
                if context and context['bug_line']:
                    print(f"    Code: {context['bug_line'].strip()[:80]}")
    
    return patterns, examples

def generate_improved_filters():
    """Generate improved filtering rules."""
    
    print("\n")
    print("="*80)
    print("RECOMMENDED IMPROVEMENTS")
    print("="*80)
    print()
    
    improvements = [
        "1. FILTER TEST/BENCHMARK FILES",
        "   - Exclude files with 'test', 'bench', 'perf' in path",
        "   - These are development/validation code, not production",
        "",
        "2. FILTER EXAMPLE/DEMO CODE",
        "   - Exclude 'example', 'demo', 'sample', 'tutorial' files",
        "   - Educational code often has intentional simplifications",
        "",
        "3. IMPROVE LIST COMPREHENSION HANDLING",
        "   - Comprehensions often have implicit bounds checking",
        "   - Pattern: [x[i] for i in range(len(x))] is safe by construction",
        "",
        "4. RECOGNIZE ITERATOR PATTERNS",
        "   - enumerate(), zip(), iter() provide safe iteration",
        "   - Lower confidence for these patterns",
        "",
        "5. STRING OPERATIONS CONTEXT",
        "   - String indexing after .split() needs different analysis",
        "   - Consider string length vs list length",
        "",
        "6. DEDUPLICATE REPORTS",
        "   - Multiple bugs at same location should be consolidated",
        "   - Currently reporting same bug multiple times",
        "",
        "7. REQUIRE DATAFLOW CONFIRMATION",
        "   - For BOUNDS: verify array source is not constant-length",
        "   - For DIV_ZERO: verify denominator source could be user-controlled",
    ]
    
    for line in improvements:
        print(line)
    
    print()
    print("="*80)
    print("ESTIMATED IMPROVEMENT")
    print("="*80)
    print()
    
    # Load data
    data = load_results()
    total_high = data['summary']['high_severity']
    
    # Estimate FP rate
    patterns, _ = identify_false_positive_patterns(data['high_confidence_findings'][:200])
    total_fps = sum(patterns.values()) - patterns['other']
    fp_rate = total_fps / min(200, len(data['high_confidence_findings']))
    
    estimated_real_tps = int(total_high * (1 - fp_rate))
    estimated_fps = total_high - estimated_real_tps
    
    print(f"Current high-severity bugs: {total_high}")
    print(f"Estimated FP rate: {fp_rate*100:.1f}%")
    print(f"Estimated real TPs: {estimated_real_tps}")
    print(f"Estimated FPs to filter: {estimated_fps}")
    print()
    print(f"After improvements:")
    print(f"  • Focus on ~{estimated_real_tps} likely real bugs")
    print(f"  • TP/FP ratio improvement: {(1-fp_rate)*100:.0f}% precision")

if __name__ == '__main__':
    patterns, examples = analyze_high_confidence_bugs()
    generate_improved_filters()
