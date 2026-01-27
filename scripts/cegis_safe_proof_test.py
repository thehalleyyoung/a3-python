#!/usr/bin/env python3
"""
Apply CEGIS barrier synthesis to tier 1 SAFE files to measure proof success rate.

This script tests whether our CEGIS synthesis can produce inductive barrier certificates
for files that were marked SAFE (meaning no bugs found, but no proof was provided).
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import analyze
from pyfromscratch.barriers.cegis import CEGISBarrierSynthesizer


def test_cegis_on_safe_file(file_path: str, bug_type: str, timeout_ms: int = 30000) -> dict:
    """
    Attempt CEGIS barrier synthesis for a file marked SAFE.
    
    Returns:
        dict with keys: success (bool), proof_found (bool), time_seconds (float), 
        iterations (int), template_used (str), error (str or None)
    """
    result = {
        'file': file_path,
        'bug_type': bug_type,
        'success': False,
        'proof_found': False,
        'time_seconds': 0.0,
        'templates_tried': 0,
        'synthesis_time_ms': 0.0,
        'barrier_name': None,
        'error': None
    }
    
    start_time = time.time()
    
    try:
        # Analyze the file - the analyzer includes barrier synthesis attempts
        file_path_obj = Path(file_path)
        analysis_result = analyze(file_path_obj, verbose=False)
        
        result['time_seconds'] = time.time() - start_time
        result['success'] = True
        
        # Check if a proof was found
        if analysis_result.verdict == 'SAFE' and analysis_result.barrier:
            result['proof_found'] = True
            result['barrier_name'] = analysis_result.barrier.name
            if analysis_result.synthesis_result:
                result['templates_tried'] = analysis_result.synthesis_result.templates_tried
                result['synthesis_time_ms'] = analysis_result.synthesis_result.synthesis_time_ms
            else:
                result['templates_tried'] = 0
                result['synthesis_time_ms'] = 0.0
        elif analysis_result.verdict == 'SAFE':
            # SAFE without barrier means synthesis didn't succeed
            result['proof_found'] = False
            if analysis_result.synthesis_result:
                result['templates_tried'] = analysis_result.synthesis_result.templates_tried
                result['synthesis_time_ms'] = analysis_result.synthesis_result.synthesis_time_ms
        
    except TimeoutError:
        result['time_seconds'] = time.time() - start_time
        result['error'] = 'timeout'
    except Exception as e:
        result['time_seconds'] = time.time() - start_time
        result['error'] = str(type(e).__name__ + ": " + str(e))
    
    return result


def main():
    # Load the list of SAFE files
    safe_files_path = Path('results/tier1_safe_files_for_cegis.json')
    if not safe_files_path.exists():
        print("Error: results/tier1_safe_files_for_cegis.json not found")
        return 1
    
    with open(safe_files_path) as f:
        safe_files = json.load(f)
    
    print(f"Testing CEGIS synthesis on {len(safe_files)} SAFE files from tier 1...")
    print("=" * 80)
    
    results = []
    proof_success_count = 0
    analysis_success_count = 0
    
    for i, item in enumerate(safe_files, 1):
        file_path = item['file']
        bug_type = item['bug_type']
        repo = item['repo']
        
        print(f"\n[{i}/{len(safe_files)}] Testing: {repo} / {Path(file_path).name}")
        print(f"  Bug type: {bug_type}")
        
        result = test_cegis_on_safe_file(file_path, bug_type, timeout_ms=30000)
        results.append(result)
        
        if result['success']:
            analysis_success_count += 1
        
        if result['proof_found']:
            proof_success_count += 1
            print(f"  ✓ PROOF: {result['barrier_name']} ({result['templates_tried']} templates, {result['synthesis_time_ms']:.1f}ms)")
        elif result['error']:
            print(f"  ✗ ERROR: {result['error']}")
        else:
            print(f"  ○ No proof found (SAFE without proof)")
        
        print(f"  Time: {result['time_seconds']:.2f}s")
        
        # Save incremental results
        if i % 10 == 0:
            with open('results/cegis_proof_test_partial.json', 'w') as f:
                json.dump({
                    'processed': i,
                    'total': len(safe_files),
                    'proof_success_count': proof_success_count,
                    'analysis_success_count': analysis_success_count,
                    'results': results
                }, f, indent=2)
    
    # Final results
    print("\n" + "=" * 80)
    print("CEGIS PROOF SYNTHESIS TEST RESULTS")
    print("=" * 80)
    print(f"Total files tested: {len(safe_files)}")
    print(f"Analyses completed: {analysis_success_count} ({analysis_success_count/len(safe_files)*100:.1f}%)")
    print(f"Proofs synthesized: {proof_success_count} ({proof_success_count/len(safe_files)*100:.1f}%)")
    print(f"No proof (still SAFE): {analysis_success_count - proof_success_count}")
    print(f"Errors/timeouts: {len(safe_files) - analysis_success_count}")
    
    # Save final results
    output_path = 'results/cegis_proof_test_iteration82.json'
    with open(output_path, 'w') as f:
        json.dump({
            'iteration': 82,
            'tested_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            'total_files': len(safe_files),
            'analysis_success_count': analysis_success_count,
            'proof_success_count': proof_success_count,
            'proof_success_rate': proof_success_count / len(safe_files) if safe_files else 0,
            'results': results
        }, f, indent=2)
    
    print(f"\nResults saved to {output_path}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
