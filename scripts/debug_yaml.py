#!/usr/bin/env python3
"""Debug YAML deserialization detection."""

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

fn = find_function(code, 'a9_lab')
if fn:
    print("=== a9_lab bytecode (lines 545-560) ===")
    dis.dis(fn)
    
    print("\n--- Call identification ---")
    analyzer = SOTAIntraproceduralAnalyzer(
        code_obj=fn,
        function_name='a9_lab',
        file_path=str(filepath),
    )
    
    instructions = list(dis.get_instructions(fn))
    for instr in instructions:
        if 'CALL' in instr.opname:
            call_name = analyzer._identify_call(instr.offset)
            print(f"  {instr.opname} at {instr.offset}: '{call_name}'")
    
    print("\n--- Running analysis ---")
    violations = analyzer.analyze()
    print(f"Found {len(violations)} violations:")
    for v in violations:
        print(f"  {v.bug_type} at line {v.line_number}: {v.sink_type.name}")
else:
    print("Function not found")
