#!/usr/bin/env python3
"""Test the SOTA analyzer on a PyGoat-like SQL injection pattern."""

from pathlib import Path
from pyfromscratch.semantics.sota_intraprocedural import SOTAIntraproceduralAnalyzer
import dis
import tempfile

# Minimal PyGoat-like SQL injection
code = '''
def sql_lab(request):
    name = request.POST.get('name')
    password = request.POST.get('pass')
    
    sql_query = "SELECT * FROM users WHERE user='" + name + "' AND pass='" + password + "'"
    
    val = login.objects.raw(sql_query)
    return val
'''

with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
    f.write(code)
    filepath = Path(f.name)

try:
    code_obj = compile(code, str(filepath), 'exec')
    # Extract sql_lab function
    for const in code_obj.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'sql_lab':
            print("Bytecode:")
            dis.dis(const)
            print("\n" + "="*60 + "\n")
            
            analyzer = SOTAIntraproceduralAnalyzer(
                code_obj=const,
                function_name='sql_lab',
                file_path=str(filepath),
                verbose=True
            )
            
            # Test call identification manually
            instructions = list(dis.get_instructions(const))
            for instr in instructions:
                if instr.opname in ('CALL', 'CALL_FUNCTION'):
                    call_name = analyzer._identify_call(instr.offset)
                    print(f"Call at offset {instr.offset}: identified as '{call_name}'")
            
            print("\n" + "="*60 + "\n")
            
            violations = analyzer.analyze()
            print(f'Found {len(violations)} violations')
            for v in violations:
                print(f'  {v.bug_type}: {v.reason}')
finally:
    filepath.unlink()
