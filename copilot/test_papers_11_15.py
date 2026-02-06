#!/usr/bin/env python3
"""Test each Paper #11-15 individually"""

from pyfromscratch.barriers.papers_11_to_15_complete import (
    IMCVerifier, CEGARVerifier, PredicateAbstractionVerifier,
    BooleanProgramVerifier, IMPACTVerifier
)

class MockMetadata:
    function_name = 'test_function'
    instructions = []
    guard_facts = {'x': ['ZERO_CHECK']}

def test_all_papers():
    metadata = MockMetadata()
    
    papers = [
        (11, 'IMC Interpolation', IMCVerifier(), 'verify_via_interpolation'),
        (12, 'CEGAR', CEGARVerifier(), 'verify_with_cegar'),
        (13, 'Predicate Abstraction', PredicateAbstractionVerifier(), 'verify_with_predicates'),
        (14, 'Boolean Programs', BooleanProgramVerifier(), 'verify_via_boolean_program'),
        (15, 'IMPACT', IMPACTVerifier(), 'verify_with_impact'),
    ]
    
    print('Testing Papers #11-15 Individual Implementations')
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
            print()
            
            results.append((paper_num, is_safe))
            
        except Exception as e:
            print(f'Paper #{paper_num} ({paper_name}):')
            print(f'  Status: ✗ ERROR')
            print(f'  Error: {str(e)[:80]}')
            print()
            results.append((paper_num, False))
    
    print('=' * 70)
    safe_count = sum(1 for _, safe in results if safe)
    print(f'Working Papers: {safe_count}/5')
    
    if safe_count >= 4:
        print('🎉 EXCELLENT - Most papers working!')
    elif safe_count >= 2:
        print('⚠️  PARTIAL - Some papers working')
    else:
        print('❌ POOR - Few papers working')
    
    return results

if __name__ == '__main__':
    test_all_papers()
