#!/usr/bin/env python3
"""Debug insecure cookie detection."""

import dis
import types
from pathlib import Path
from pyfromscratch.semantics.sota_intraprocedural import SOTAIntraproceduralAnalyzer

filepath = Path('external_tools/pygoat/introduction/views.py')
source = filepath.read_text()
code = compile(source, str(filepath), 'exec')

def find_function(code_obj, name):
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name == name:
                return const
            result = find_function(const, name)
            if result:
                return result
    return None

# The set_cookie is in auth_lab_signup function around line 286
fn = find_function(code, 'auth_lab_signup')
if fn:
    print("=== auth_lab_signup bytecode (looking for set_cookie) ===")
    instructions = list(dis.get_instructions(fn))
    for instr in instructions:
        if 'set_cookie' in str(instr) or instr.opname in ('CALL', 'CALL_KW'):
            print(f"  {instr.offset:4d} {instr.opname:20s} {instr.argval}")
    
    print("\n--- Running analysis ---")
    analyzer = SOTAIntraproceduralAnalyzer(
        code_obj=fn,
        function_name='auth_lab_signup',
        file_path=str(filepath),
        verbose=True,
    )
    
    violations = analyzer.analyze()
    print(f"\nFound {len(violations)} violations:")
    for v in violations:
        print(f"  {v.bug_type} at line {v.line_number}: {v.reason[:80]}...")
else:
    print("Function not found")
