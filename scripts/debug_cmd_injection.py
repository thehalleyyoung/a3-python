#!/usr/bin/env python3
"""Debug command injection detection in PyGoat-like pattern."""

from pyfromscratch.semantics.sota_intraprocedural import (
    analyze_function_sota, SOTAIntraproceduralAnalyzer
)
import dis
import tempfile
from pathlib import Path

# Simplified cmd_lab
code = '''
def cmd_lab(request):
    if request.user.is_authenticated:
        if request.method == "POST":
            domain = request.POST.get("domain")
            command = "dig {}".format(domain)
            import subprocess
            process = subprocess.Popen(command, shell=True)
'''

with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
    f.write(code)
    filepath = Path(f.name)

code_obj = compile(code, str(filepath), 'exec')
for const in code_obj.co_consts:
    if hasattr(const, 'co_name') and const.co_name == 'cmd_lab':
        print('Bytecode:')
        dis.dis(const)
        print()
        
        analyzer = SOTAIntraproceduralAnalyzer(
            code_obj=const,
            function_name='cmd_lab',
            file_path=str(filepath),
            verbose=True,
            max_iterations=1000
        )
        
        # Check call identification
        print('Call identification:')
        instructions = list(dis.get_instructions(const))
        for instr in instructions:
            if instr.opname == 'CALL':
                call_name = analyzer._identify_call(instr.offset)
                print(f'  Call at offset {instr.offset}: {call_name}')
        
        print()
        violations = analyzer.analyze()
        print(f'Found {len(violations)} violations')
        for v in violations:
            print(f'  {v.bug_type}: {v.reason[:80]}')
        
filepath.unlink()
