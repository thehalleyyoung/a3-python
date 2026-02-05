#!/usr/bin/env python3
"""
Run EXTREME verification on DeepSpeed with ALL 20 SOTA papers.
Records detailed results and analysis.
"""

import sys
import json
import time
import logging
from pathlib import Path
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.barriers.extreme_verification import ExtremeContextVerifier

def main():
    print("=" * 80)
    print("EXTREME VERIFICATION ON DEEPSPEED")
    print("Using ALL 20 SOTA Papers for Maximum Precision")
    print("=" * 80)
    print()
    
    deepspeed_path = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools/DeepSpeed')
    
    if not deepspeed_path.exists():
        logger.error(f"DeepSpeed not found at {deepspeed_path}")
        return
    
    logger.info(f"Analyzing DeepSpeed at: {deepspeed_path}")
    logger.info("Initializing tracker with extreme verification...")
    
    start_time = time.time()
    
    # Create tracker with extreme verification enabled
    tracker = InterproceduralBugTracker.from_project(
        root_path=deepspeed_path,
        entry_points=None
    )
    
    # Enable extreme verification and connect to tracker's call graph
    extreme_verifier = ExtremeContextVerifier()
    extreme_verifier.call_graph = tracker.call_graph
    # Note: crash_summary_tracker is used in strategy 1, but we'll use crash_summaries directly
    tracker.verifier = extreme_verifier
    
    logger.info("Starting bug detection (non-security only)...")
    
    # Find bugs
    try:
        bugs = tracker.find_all_bugs(only_non_security=True)
    except Exception as e:
        logger.error(f"Error during bug detection: {e}")
        import traceback
        traceback.print_exc()
        return
    
    elapsed = time.time() - start_time
    
    # Define severity mapping
    def get_severity(bug):
        """Calculate severity based on bug type and confidence."""
        high_severity_types = ['BOUNDS', 'DIV_ZERO', 'NULL_PTR', 'SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL']
        medium_severity_types = ['WEAK_CRYPTO', 'UNSAFE_DESERIALIZATION', 'XSS', 'SSRF']
        
        if bug.confidence >= 0.8:
            if bug.bug_type in high_severity_types:
                return 'HIGH'
            elif bug.bug_type in medium_severity_types:
                return 'MEDIUM'
            else:
                return 'LOW'
        elif bug.confidence >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    # Analyze results
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    
    total_bugs = len(bugs)
    high_bugs = [b for b in bugs if get_severity(b) == 'HIGH']
    medium_bugs = [b for b in bugs if get_severity(b) == 'MEDIUM']
    low_bugs = [b for b in bugs if get_severity(b) == 'LOW']
    
    print(f"\nTotal bugs found: {total_bugs}")
    print(f"  HIGH severity:   {len(high_bugs)}")
    print(f"  MEDIUM severity: {len(medium_bugs)}")
    print(f"  LOW severity:    {len(low_bugs)}")
    
    # Breakdown by bug type
    print("\n" + "-" * 80)
    print("Bug Types (HIGH severity only):")
    print("-" * 80)
    
    bug_type_counts = defaultdict(int)
    for bug in high_bugs:
        bug_type_counts[bug.bug_type] += 1
    
    for bug_type in sorted(bug_type_counts.keys()):
        count = bug_type_counts[bug_type]
        print(f"  {bug_type:25s}: {count:4d}")
    
    # Detailed breakdown
    print("\n" + "-" * 80)
    print("All Bug Types (all severities):")
    print("-" * 80)
    
    all_bug_types = defaultdict(lambda: {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
    for bug in bugs:
        severity = get_severity(bug)
        all_bug_types[bug.bug_type][severity] += 1
    
    for bug_type in sorted(all_bug_types.keys()):
        counts = all_bug_types[bug_type]
        total = sum(counts.values())
        print(f"  {bug_type:25s}: {total:4d} (H:{counts['HIGH']:3d} M:{counts['MEDIUM']:3d} L:{counts['LOW']:3d})")
    
    # Verification statistics
    print("\n" + "-" * 80)
    print("Verification Statistics:")
    print("-" * 80)
    
    verifier = tracker.verifier
    if hasattr(verifier, '_verification_cache'):
        cache_size = len(verifier._verification_cache)
        print(f"  Verification cache entries: {cache_size}")
    
    if hasattr(verifier, 'unified_engine'):
        print(f"  Unified engine enabled: YES")
        print(f"  Real SOTA engines: {verifier.use_real_engines}")
    
    print(f"\nAnalysis time: {elapsed:.2f}s")
    
    # Save detailed results
    results_file = Path(__file__).parent / 'results' / 'extreme_deepspeed_results.json'
    results_file.parent.mkdir(parents=True, exist_ok=True)
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'repository': str(deepspeed_path),
        'analysis_time_seconds': elapsed,
        'total_bugs': total_bugs,
        'severity_breakdown': {
            'HIGH': len(high_bugs),
            'MEDIUM': len(medium_bugs),
            'LOW': len(low_bugs)
        },
        'bug_types': {
            bug_type: {
                'total': sum(counts.values()),
                'HIGH': counts['HIGH'],
                'MEDIUM': counts['MEDIUM'],
                'LOW': counts['LOW']
            }
            for bug_type, counts in all_bug_types.items()
        },
        'high_severity_bugs': [
            {
                'type': bug.bug_type,
                'function': bug.crash_function,
                'variable': bug.bug_variable or 'unknown',
                'location': bug.crash_location,
                'reason': bug.reason,
                'confidence': bug.confidence
            }
            for bug in high_bugs[:50]  # Save first 50 HIGH bugs
        ],
        'verification_config': {
            'extreme_verification': True,
            'all_20_sota_papers': True,
            'cache_enabled': hasattr(verifier, '_verification_cache'),
            'real_engines': getattr(verifier, 'use_real_engines', False)
        }
    }
    
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Detailed results saved to: {results_file}")
    
    # Print sample HIGH bugs
    if high_bugs:
        print("\n" + "=" * 80)
        print("Sample HIGH Severity Bugs (first 10):")
        print("=" * 80)
        
        for i, bug in enumerate(high_bugs[:10], 1):
            print(f"\n{i}. {bug.bug_type} in {bug.crash_function}")
            print(f"   Variable: {bug.bug_variable or 'unknown'}")
            print(f"   Location: {bug.crash_location}")
            print(f"   Confidence: {bug.confidence:.2f}")
            print(f"   Reason: {bug.reason[:100]}..." if len(bug.reason) > 100 else f"   Reason: {bug.reason}")
    
    # Comparison with previous analyses
    print("\n" + "=" * 80)
    print("Analysis Complete!")
    print("=" * 80)
    print(f"\nResults: {results_file}")
    print(f"Total bugs: {total_bugs}")
    print(f"HIGH severity: {len(high_bugs)}")
    print(f"Time: {elapsed:.2f}s")
    
    return results


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
