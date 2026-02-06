#!/usr/bin/env python3
"""
Analyze what each of the 25 papers excels at finding.

This script tests each paper's technique on different bug types and contexts
to understand:
1. Which papers are best for which bug types
2. What contexts each paper excels in
3. How to expand integration for each paper
"""

import pickle
from collections import defaultdict
from pyfromscratch.barriers.fast_barrier_filters import FastBarrierFilterPipeline

def load_summaries():
    with open('results/deepspeed_crash_summaries.pkl', 'rb') as f:
        return pickle.load(f)

def create_diverse_test_cases(summaries):
    """Create diverse test cases covering different bug types and contexts."""
    test_cases = []
    
    # Sample functions from different contexts
    contexts = {
        'test': [],
        'private': [],
        'public': [],
        'magic': [],
        'inference': [],
    }
    
    for func_name, summary in summaries.items():
        if 'test_' in func_name.lower():
            contexts['test'].append((func_name, summary))
        elif func_name.startswith('_') and not func_name.startswith('__'):
            contexts['private'].append((func_name, summary))
        elif '__' in func_name:
            contexts['magic'].append((func_name, summary))
        elif 'inference' in func_name.lower():
            contexts['inference'].append((func_name, summary))
        else:
            contexts['public'].append((func_name, summary))
    
    # Create test cases for each context and bug type combo
    bug_types = ['DIV_ZERO', 'NULL_PTR', 'VALUE_ERROR', 'RUNTIME_ERROR', 'BOUNDS']
    variables = ['param_0', 'count', 'size', 'length', 'index', 'result', 'data']
    
    for context_name, funcs in contexts.items():
        if funcs:
            # Take up to 5 functions from each context
            for func_name, summary in funcs[:5]:
                for bug_type in bug_types:
                    for var in variables[:3]:  # Test 3 variable names per bug type
                        test_cases.append({
                            'context': context_name,
                            'function': func_name,
                            'bug_type': bug_type,
                            'variable': var,
                            'summary': summary,
                        })
    
    return test_cases

def test_paper_on_case(pipeline, technique_name, test_case):
    """Test a specific technique on a test case."""
    summary = test_case['summary']
    bug_type = test_case['bug_type']
    variable = test_case['variable']
    
    # Test individual technique
    if technique_name == 'likely_invariants':
        is_safe, conf = pipeline.likely_invariants.proves_safe(bug_type, variable)
    elif technique_name == 'separation_logic':
        is_safe, conf = pipeline.separation_logic.proves_safe(bug_type, variable, summary)
    elif technique_name == 'refinement_types':
        is_safe, conf = pipeline.refinement_types.proves_safe(bug_type, variable, summary)
    elif technique_name == 'interval_analysis':
        is_safe, conf = pipeline.interval_analysis.proves_safe(bug_type, variable, summary)
    elif technique_name == 'stochastic':
        is_safe, conf = pipeline.stochastic.proves_safe(bug_type, variable, summary)
    else:
        return False, 0.0
    
    return is_safe, conf

def analyze_paper_strengths():
    """Analyze what each paper excels at."""
    print("="*80)
    print("ANALYZING PAPER CONTRIBUTIONS (Papers #21-25)")
    print("="*80)
    print()
    
    # Load data
    print("Loading summaries...")
    summaries = load_summaries()
    inference_funcs = {k: v for k, v in summaries.items()
                      if '.inference' in k.lower() or 'inference.' in k.lower()}
    print(f"  Loaded {len(inference_funcs)} inference functions")
    print()
    
    # Create pipeline
    pipeline = FastBarrierFilterPipeline()
    pipeline.learn_from_codebase(inference_funcs)
    print("  ✓ Pipeline trained")
    print()
    
    # Create diverse test cases
    print("Creating diverse test cases...")
    test_cases = create_diverse_test_cases(inference_funcs)
    print(f"  Created {len(test_cases)} test cases")
    print()
    
    # Test each paper
    papers = {
        'likely_invariants': 'Paper #21: Likely Invariants',
        'separation_logic': 'Paper #22: Separation Logic',
        'refinement_types': 'Paper #23: Refinement Types',
        'interval_analysis': 'Paper #24: Interval Analysis',
        'stochastic': 'Paper #25: Stochastic Barriers',
    }
    
    # Track results
    paper_results = defaultdict(lambda: {
        'total': 0,
        'safe': 0,
        'by_bug_type': defaultdict(int),
        'by_context': defaultdict(int),
        'by_variable': defaultdict(int),
        'confidences': [],
    })
    
    print("Testing each paper on all test cases...")
    print("-"*80)
    
    for paper_name, paper_title in papers.items():
        print(f"\nTesting {paper_title}...")
        
        for test_case in test_cases:
            is_safe, conf = test_paper_on_case(pipeline, paper_name, test_case)
            
            results = paper_results[paper_name]
            results['total'] += 1
            
            if is_safe:
                results['safe'] += 1
                results['by_bug_type'][test_case['bug_type']] += 1
                results['by_context'][test_case['context']] += 1
                results['by_variable'][test_case['variable']] += 1
                results['confidences'].append(conf)
        
        total = paper_results[paper_name]['total']
        safe = paper_results[paper_name]['safe']
        pct = 100 * safe / max(total, 1)
        print(f"  Found {safe}/{total} FPs ({pct:.1f}%)")
    
    print()
    print("="*80)
    print("DETAILED ANALYSIS BY PAPER")
    print("="*80)
    print()
    
    for paper_name, paper_title in papers.items():
        results = paper_results[paper_name]
        
        print(f"{paper_title}")
        print("-"*80)
        
        total = results['total']
        safe = results['safe']
        success_rate = 100 * safe / max(total, 1)
        
        print(f"Success Rate: {safe}/{total} ({success_rate:.1f}%)")
        
        if results['confidences']:
            avg_conf = sum(results['confidences']) / len(results['confidences'])
            min_conf = min(results['confidences'])
            max_conf = max(results['confidences'])
            print(f"Confidence: avg={avg_conf:.1%}, min={min_conf:.1%}, max={max_conf:.1%}")
        
        print()
        
        # Best bug types
        if results['by_bug_type']:
            print("  Best Bug Types:")
            sorted_bugs = sorted(results['by_bug_type'].items(), key=lambda x: x[1], reverse=True)
            for bug_type, count in sorted_bugs[:3]:
                pct = 100 * count / safe if safe > 0 else 0
                print(f"    {bug_type:15s}: {count:3d} FPs ({pct:.1f}%)")
        
        # Best contexts
        if results['by_context']:
            print("  Best Contexts:")
            sorted_contexts = sorted(results['by_context'].items(), key=lambda x: x[1], reverse=True)
            for context, count in sorted_contexts[:3]:
                pct = 100 * count / safe if safe > 0 else 0
                print(f"    {context:15s}: {count:3d} FPs ({pct:.1f}%)")
        
        # Best variables
        if results['by_variable']:
            print("  Best Variables:")
            sorted_vars = sorted(results['by_variable'].items(), key=lambda x: x[1], reverse=True)
            for var, count in sorted_vars[:3]:
                pct = 100 * count / safe if safe > 0 else 0
                print(f"    {var:15s}: {count:3d} FPs ({pct:.1f}%)")
        
        print()
        print()
    
    # Summary comparison
    print("="*80)
    print("COMPARATIVE SUMMARY")
    print("="*80)
    print()
    
    print(f"{'Paper':<40s} {'Success Rate':>15s} {'Avg Confidence':>15s}")
    print("-"*80)
    
    for paper_name, paper_title in papers.items():
        results = paper_results[paper_name]
        total = results['total']
        safe = results['safe']
        success_rate = 100 * safe / max(total, 1)
        
        if results['confidences']:
            avg_conf = sum(results['confidences']) / len(results['confidences'])
            conf_str = f"{avg_conf:.1%}"
        else:
            conf_str = "N/A"
        
        print(f"{paper_title:<40s} {success_rate:>14.1f}% {conf_str:>15s}")
    
    print()
    
    # Recommendations
    print("="*80)
    print("INTEGRATION EXPANSION RECOMMENDATIONS")
    print("="*80)
    print()
    
    for paper_name, paper_title in papers.items():
        results = paper_results[paper_name]
        safe = results['safe']
        
        print(f"{paper_title}:")
        
        if safe == 0:
            print("  ⚠ NOT CURRENTLY ACTIVE")
            print("  Recommendations:")
            
            if paper_name == 'likely_invariants':
                print("    - Need more training data with bytecode instructions")
                print("    - Implement fallback: infer from function signatures")
                print("    - Add name-based heuristics (count, size, length)")
                print("    - Excel at: DIV_ZERO with validated divisors")
            
            elif paper_name == 'separation_logic':
                print("    - Add constructor pattern recognition without bytecode")
                print("    - Infer ownership from parameter position (param_0 = self)")
                print("    - Track return value ownership from function name")
                print("    - Excel at: NULL_PTR in OOP code, fresh allocations")
            
            elif paper_name == 'refinement_types':
                print("    - Parse more docstring patterns")
                print("    - Infer from function name (get_positive_count → positive)")
                print("    - Add Pydantic/dataclass validator detection")
                print("    - Excel at: Annotated code, validated inputs")
            
            elif paper_name == 'interval_analysis':
                print("    - Add symbolic interval propagation")
                print("    - Infer ranges from variable names (index → [0, ∞))")
                print("    - Track min/max through function calls")
                print("    - Excel at: DIV_ZERO, BOUNDS with numeric variables")
        
        elif safe < results['total'] * 0.5:
            print("  ⚠ UNDERUTILIZED (< 50% success rate)")
            print("  Recommendations:")
            print("    - Lower confidence threshold")
            print("    - Add more heuristics")
            print("    - Combine with other techniques")
        
        else:
            print("  ✓ WORKING WELL")
            if results['by_bug_type']:
                best_bug = max(results['by_bug_type'].items(), key=lambda x: x[1])
                print(f"    - Excels at: {best_bug[0]} ({best_bug[1]} FPs)")
            if results['by_context']:
                best_context = max(results['by_context'].items(), key=lambda x: x[1])
                print(f"    - Best in: {best_context[0]} functions ({best_context[1]} FPs)")
        
        print()
    
    return paper_results

if __name__ == '__main__':
    results = analyze_paper_strengths()
