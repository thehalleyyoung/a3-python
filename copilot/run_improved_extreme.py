#!/usr/bin/env python3
"""
Run extreme verification with improved false positive reduction on DeepSpeed.
Compare results before and after improvements.
"""
import json
import time
from pathlib import Path
from collections import defaultdict

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.barriers.extreme_verification import ExtremeContextVerifier

def load_previous_results():
    """Load previous results for comparison"""
    results_path = Path("results/extreme_deepspeed_results.json")
    if not results_path.exists():
        return None
    
    with open(results_path) as f:
        data = json.load(f)
    
    # Convert to expected format
    return {
        'total_bugs_found': data.get('total_bugs', 0),
        'high_severity': data.get('severity_breakdown', {}).get('HIGH', 0),
        'medium_severity': data.get('severity_breakdown', {}).get('MEDIUM', 0),
        'low_severity': data.get('severity_breakdown', {}).get('LOW', 0),
        'bugs': data.get('high_severity_bugs', [])
    }

def run_improved_verification():
    """Run verification with improved FP reduction"""
    print("=" * 80)
    print("RUNNING IMPROVED EXTREME VERIFICATION ON DEEPSPEED")
    print("=" * 80)
    
    deepspeed_path = Path("/Users/halleyyoung/Documents/PythonFromScratch/external_tools/DeepSpeed")
    
    # Load previous results
    previous_results = load_previous_results()
    if previous_results:
        prev_total = previous_results.get('total_bugs_found', 0)
        prev_high = previous_results.get('high_severity', 0)
        print(f"\nPrevious Results: {prev_total} total bugs, {prev_high} HIGH severity")
    
    # Initialize tracker
    print(f"\n[1/3] Initializing interprocedural bug tracker...")
    start_time = time.time()
    
    tracker = InterproceduralBugTracker.from_project(
        root_path=deepspeed_path,
        entry_points=None
    )
    
    # Enable extreme verification
    verifier = ExtremeContextVerifier()
    verifier.call_graph = tracker.call_graph
    tracker.verifier = verifier
    
    # Run analysis
    print(f"[2/3] Running interprocedural analysis...")
    all_bugs_raw = tracker.find_all_bugs(only_non_security=True)
    
    analysis_time = time.time() - start_time
    print(f"      Analysis completed in {analysis_time:.1f} seconds")
    
    # Convert to dict format
    all_bugs = []
    for bug in all_bugs_raw:
        # Parse location (format: "file:line")
        if ':' in bug.crash_location:
            file_path, line_str = bug.crash_location.rsplit(':', 1)
            try:
                line_num = int(line_str)
            except:
                line_num = 0
        else:
            file_path = bug.crash_location
            line_num = 0
        
        all_bugs.append({
            'bug_type': bug.bug_type,
            'file': file_path,
            'line': line_num,
            'message': bug.reason,
            'function': bug.crash_function,
            'variable': bug.bug_variable or '',
            'confidence': bug.confidence
        })
    
    print(f"\n[3/3] Re-verifying {len(all_bugs)} bugs with improved FP reduction strategies...")
    
    # Now manually re-verify each bug with improved extreme verification
    # to see if our enhancements eliminate any false positives
    verified_bugs = []
    eliminated_by_strategy = defaultdict(int)
    
    verify_start = time.time()
    for i, bug in enumerate(all_bugs, 1):
        if i % 50 == 0:
            print(f"      Progress: {i}/{len(all_bugs)} bugs re-verified...")
        
        # Get crash summary for this bug - keyed by function name
        func_name = bug['function']
        crash_summary = tracker.crash_summaries.get(func_name)
        
        # Fetch source code from the file
        source_code = None
        if crash_summary:
            try:
                file_path = Path(bug['file'])
                if file_path.exists():
                    source_code = file_path.read_text()
            except:
                pass
        
        if crash_summary and source_code:
            # Re-verify with improved strategies
            # verify_bug_extreme signature: (bug_type, bug_variable, crash_summary, call_chain_summaries, code_object, source_code)
            result = verifier.verify_bug_extreme(
                bug['bug_type'],
                bug['variable'],
                crash_summary,
                [],  # Empty call chain for intraprocedural re-verification
                None,  # code_object
                source_code  # Pass the actual source code for pattern matching
            )
            
            if result.is_safe:
                # False positive eliminated by improved strategies!
                if result.proof_method:
                    strategy = result.proof_method.split(':')[0] if ':' in result.proof_method else result.proof_method
                    eliminated_by_strategy[strategy] += 1
                continue  # Don't add to verified_bugs
        
        # Bug survived re-verification (or couldn't be re-verified)
        confidence = bug.get('confidence', 0.5)
        
        if confidence > 0.7:
            bug['severity'] = 'HIGH'
        elif confidence > 0.4:
            bug['severity'] = 'MEDIUM'
        else:
            bug['severity'] = 'LOW'
        
        verified_bugs.append(bug)
    
    verify_time = time.time() - verify_start
    total_time = time.time() - start_time
    
    eliminated = len(all_bugs) - len(verified_bugs)
    
    print(f"      Re-verification completed in {verify_time:.1f} seconds")
    
    # Analyze results
    high_severity = [b for b in verified_bugs if b['severity'] == 'HIGH']
    medium_severity = [b for b in verified_bugs if b['severity'] == 'MEDIUM']
    low_severity = [b for b in verified_bugs if b['severity'] == 'LOW']
    
    print("\n" + "=" * 80)
    print("IMPROVED RESULTS")
    print("=" * 80)
    print(f"Total bugs before re-verification: {len(all_bugs)}")
    print(f"Bugs after improved strategies: {len(verified_bugs)}")
    print(f"False positives eliminated: {eliminated} ({100*eliminated/len(all_bugs) if all_bugs else 0:.1f}%)")
    print(f"\nSeverity breakdown:")
    print(f"  HIGH:   {len(high_severity)}")
    print(f"  MEDIUM: {len(medium_severity)}")
    print(f"  LOW:    {len(low_severity)}")
    
    if eliminated_by_strategy:
        print(f"\nFalse positives eliminated by strategy:")
        for strategy, count in sorted(eliminated_by_strategy.items(), key=lambda x: -x[1]):
            print(f"  {strategy}: {count}")
    
    print(f"\nExecution time: {total_time:.1f} seconds")
    
    # Compare with previous results
    if previous_results:
        prev_high = previous_results.get('high_severity', 0)
        improvement = prev_high - len(high_severity)
        improvement_pct = 100 * improvement / prev_high if prev_high > 0 else 0
        
        print("\n" + "=" * 80)
        print("IMPROVEMENT COMPARISON")
        print("=" * 80)
        print(f"Previous HIGH severity bugs: {prev_high}")
        print(f"Improved HIGH severity bugs: {len(high_severity)}")
        print(f"Reduction: {improvement} bugs ({improvement_pct:.1f}%)")
        print("=" * 80)
    
    # Save results
    results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_bugs_before_improvement': len(all_bugs),
        'total_bugs_found': len(verified_bugs),
        'false_positives_eliminated': eliminated,
        'high_severity': len(high_severity),
        'medium_severity': len(medium_severity),
        'low_severity': len(low_severity),
        'execution_time_seconds': total_time,
        'eliminated_by_strategy': dict(eliminated_by_strategy),
        'bugs': verified_bugs[:100]  # Save first 100 for inspection
    }
    
    output_path = Path("results/improved_extreme_results.json")
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
    
    # Generate detailed report
    report_path = Path("IMPROVED_EXTREME_VERIFICATION.md")
    with open(report_path, 'w') as f:
        f.write("# Improved Extreme Verification Results\n\n")
        f.write(f"**Date:** {results['timestamp']}\n\n")
        f.write("## Summary\n\n")
        f.write(f"- **Total bugs before improvement:** {len(all_bugs)}\n")
        f.write(f"- **Bugs after improved FP reduction:** {len(verified_bugs)}\n")
        f.write(f"- **False positives eliminated:** {eliminated} ({100*eliminated/len(all_bugs) if all_bugs else 0:.1f}%)\n")
        f.write(f"- **Execution time:** {total_time:.1f} seconds\n\n")
        
        f.write("## Severity Breakdown\n\n")
        f.write(f"| Severity | Count | Percentage |\n")
        f.write(f"|----------|-------|------------|\n")
        if verified_bugs:
            f.write(f"| HIGH     | {len(high_severity)} | {100*len(high_severity)/len(verified_bugs):.1f}% |\n")
            f.write(f"| MEDIUM   | {len(medium_severity)} | {100*len(medium_severity)/len(verified_bugs):.1f}% |\n")
            f.write(f"| LOW      | {len(low_severity)} | {100*len(low_severity)/len(verified_bugs):.1f}% |\n\n")
        
        if eliminated_by_strategy:
            f.write("## False Positive Elimination by Strategy\n\n")
            for strategy, count in sorted(eliminated_by_strategy.items(), key=lambda x: -x[1]):
                pct = 100 * count / eliminated if eliminated > 0 else 0
                f.write(f"- **{strategy}:** {count} bugs ({pct:.1f}%)\n")
            f.write("\n")
        
        f.write("\n## Improvements Made\n\n")
        f.write("1. **Enhanced Safe Idiom Detection (STRATEGY 1)**\n")
        f.write("   - Now properly detects `max(x, epsilon)` patterns with actual epsilon parsing\n")
        f.write("   - Recognizes `abs(x) + constant` patterns\n")
        f.write("   - Detects `x or fallback` with nonzero fallback\n")
        f.write("   - Validates division by numeric constants\n\n")
        
        f.write("2. **Torch/Numpy Contract Validation (STRATEGY 5)**\n")
        f.write("   - Detects alignment constants in I/O operations\n")
        f.write("   - Understands torch operations that guarantee positive results\n")
        f.write("   - Validates configuration values\n\n")
        
        if previous_results:
            prev_total = previous_results.get('total_bugs_found', 0)
            prev_high = previous_results.get('high_severity', 0)
            f.write("## Comparison with Previous Run\n\n")
            f.write(f"| Metric | Previous | Improved | Change |\n")
            f.write(f"|--------|----------|----------|--------|\n")
            f.write(f"| Total Bugs | {prev_total} | {len(verified_bugs)} | {len(verified_bugs) - prev_total} |\n")
            f.write(f"| HIGH Severity | {prev_high} | {len(high_severity)} | {len(high_severity) - prev_high} |\n")
            improvement_pct = 100 * (prev_high - len(high_severity)) / prev_high if prev_high > 0 else 0
            f.write(f"| FP Reduction | - | - | {improvement_pct:.1f}% |\n\n")
        
        f.write("## Sample HIGH Severity Bugs\n\n")
        for i, bug in enumerate(high_severity[:10], 1):
            f.write(f"### Bug #{i}: {bug['bug_type']}\n\n")
            f.write(f"- **File:** `{bug['file']}`\n")
            f.write(f"- **Line:** {bug['line']}\n")
            f.write(f"- **Function:** `{bug['function']}`\n")
            if bug.get('variable'):
                f.write(f"- **Variable:** `{bug['variable']}`\n")
            f.write(f"- **Confidence:** {bug['confidence']:.2f}\n")
            f.write(f"- **Message:** {bug['message']}\n\n")
    
    print(f"Detailed report saved to: {report_path}")
    
    return results

if __name__ == "__main__":
    run_improved_verification()
