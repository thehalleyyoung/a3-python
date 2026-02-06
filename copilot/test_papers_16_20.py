#!/usr/bin/env python3
"""Test each Paper #16-20 individually"""

from pyfromscratch.barriers.papers_16_to_20_complete import (
    CHCSolver, ICELearner, HoudiniVerifier, SyGuSSynthesizer,
    AssumeGuaranteeVerifier, Papers16to20UnifiedEngine
)

class MockMetadata:
    function_name = 'test_function'
    instructions = []
    guard_facts = {'x': ['ZERO_CHECK']}

def test_all_papers():
    metadata = MockMetadata()
    
    papers = [
        (16, 'CHC Solving', CHCSolver(), 'verify_via_chc'),
        (17, 'ICE Learning', ICELearner(), 'verify_with_ice'),
        (18, 'Houdini', HoudiniVerifier(), 'verify_via_houdini'),
        (19, 'SyGuS', SyGuSSynthesizer(), 'verify_via_sygus'),
        (20, 'Assume-Guarantee', AssumeGuaranteeVerifier(), 'verify_assume_guarantee'),
    ]
    
    print('Testing Papers #16-20 Individual Implementations')
    print('=' * 70)
    
    results = []
    for paper_num, paper_name, verifier, method_name in papers:
        try:
            method = getattr(verifier, method_name)
            is_safe, certificate = method('DIV_ZERO', 'x', metadata)
            
            status = '✓ SAFE' if is_safe else '✗ UNKNOWN'
            cert_type = certificate.get('type', 'none') if isinstance(certificate, dict) else 'none'
            
            print(f'Paper #{paper_num} ({paper_name}):')
            print(f'  Status: {status}')
            print(f'  Certificate: {cert_type}')
            if is_safe and isinstance(certificate, dict):
                for key, val in list(certificate.items())[:3]:
                    if key != 'type':
                        print(f'  {key}: {val}')
            print()
            
            results.append((paper_num, is_safe))
            
        except Exception as e:
            print(f'Paper #{paper_num} ({paper_name}):')
            print(f'  Status: ✗ ERROR')
            print(f'  Error: {str(e)[:80]}')
            print()
            results.append((paper_num, False))
    
    print('=' * 70)
    print('UNIFIED ENGINE TEST')
    print('=' * 70)
    
    try:
        engine = Papers16to20UnifiedEngine()
        is_safe, paper_name, cert = engine.verify_safety('DIV_ZERO', 'x', metadata)
        
        print(f'Result: {paper_name}')
        print(f'Safe: {is_safe}')
        print(f'Certificate: {cert}')
        print()
        
        unified_works = is_safe
    except Exception as e:
        print(f'ERROR: {e}')
        unified_works = False
    
    print('=' * 70)
    safe_count = sum(1 for _, safe in results if safe)
    print(f'Working Papers: {safe_count}/5')
    print(f'Unified Engine: {"✓ Working" if unified_works else "✗ Failed"}')
    
    if safe_count >= 4:
        print('🎉 EXCELLENT - Most papers working!')
    elif safe_count >= 2:
        print('⚠️  PARTIAL - Some papers working')
    else:
        print('❌ POOR - Few papers working')
    
    return results

if __name__ == '__main__':
    test_all_papers()
