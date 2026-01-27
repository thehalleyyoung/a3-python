#!/usr/bin/env python3
"""Debug XXE detection."""

import dis
import types
from pathlib import Path
from pyfromscratch.semantics.sota_intraprocedural import (
    SOTAIntraproceduralAnalyzer,
)
from pyfromscratch.contracts.security_lattice import (
    is_security_sink,
    get_sink_contract,
)

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

fn = find_function(code, 'xxe_parse')
if fn:
    print("=== xxe_parse analysis ===")
    
    analyzer = SOTAIntraproceduralAnalyzer(
        code_obj=fn,
        function_name='xxe_parse',
        file_path=str(filepath),
    )
    
    print("\n--- Call identification ---")
    instructions = list(dis.get_instructions(fn))
    for instr in instructions:
        if 'CALL' in instr.opname:
            call_name = analyzer._identify_call(instr.offset)
            is_sink = is_security_sink(call_name)
            print(f"  {instr.opname} at {instr.offset}: '{call_name}' (is_sink={is_sink})")
            
            # Also try with just the short name
            short_name = call_name.split('.')[-1] if '.' in call_name else call_name
            is_sink_short = is_security_sink(short_name)
            if is_sink_short:
                print(f"    -> Short name '{short_name}' is a sink")
    
    print("\n--- Checking if parseString is registered ---")
    names_to_check = [
        'parseString',
        'xml.dom.pulldom.parseString',
        'pulldom.parseString',
    ]
    for name in names_to_check:
        contract = get_sink_contract(name)
        print(f"  '{name}': {contract}")
    
    print("\n--- Running analysis ---")
    violations = analyzer.analyze()
    print(f"Found {len(violations)} violations:")
    for v in violations:
        print(f"  {v.bug_type} at line {v.line_number}: {v.sink_type.name}")
else:
    print("Function not found")
