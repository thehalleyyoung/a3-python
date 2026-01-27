#!/usr/bin/env python3
"""Debug command injection detection in cmd_lab."""

import dis
import types
from pathlib import Path
from pyfromscratch.semantics.sota_intraprocedural import (
    SOTAIntraproceduralAnalyzer,
    analyze_function_sota,
)

# Extract cmd_lab function from PyGoat
filepath = Path('external_tools/pygoat/introduction/views.py')
source = filepath.read_text()
code = compile(source, str(filepath), 'exec')

def find_function(code_obj, name):
    """Recursively find a function by name."""
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name == name:
                return const
            # Recurse
            result = find_function(const, name)
            if result:
                return result
    return None

cmd_lab_code = find_function(code, 'cmd_lab')

if not cmd_lab_code:
    print("Could not find cmd_lab function!")
    exit(1)

print("=== cmd_lab bytecode ===")
dis.dis(cmd_lab_code)

print("\n" + "="*60)
print("=== Parameters ===")
print(f"co_varnames: {cmd_lab_code.co_varnames}")
print(f"co_argcount: {cmd_lab_code.co_argcount}")

print("\n" + "="*60)
print("=== Running SOTA analysis with verbose=True ===")

analyzer = SOTAIntraproceduralAnalyzer(
    code_obj=cmd_lab_code,
    function_name='cmd_lab',
    file_path=str(filepath),
    verbose=True,
    max_iterations=2000,  # More iterations for complex CFG
)

# Check what calls are identified
print("\n=== Call identification ===")
instructions = list(dis.get_instructions(cmd_lab_code))
for instr in instructions:
    if 'CALL' in instr.opname:
        call_name = analyzer._identify_call(instr.offset)
        print(f"  {instr.opname} at offset {instr.offset}: '{call_name}'")

print("\n" + "="*60)
print("=== Running analysis with detailed tracing ===")

# Patch the analyzer to add detailed tracing
original_transfer = analyzer._transfer
def traced_transfer(instr, state):
    result = original_transfer(instr, state)
    # Track key assignments
    if instr.opname == 'STORE_FAST' and instr.arg in (1, 2, 3):  # domain, os, command
        var_name = analyzer.code_obj.co_varnames[instr.arg]
        label = result.get_local(instr.arg)
        print(f"  STORE_FAST {var_name}: tau={label.tau:#x}")
    if instr.opname in ('CALL', 'CALL_KW'):
        call_name = analyzer._identify_call(instr.offset)
        if 'POST.get' in call_name or 'Popen' in call_name:
            print(f"  {instr.opname} {call_name} at offset {instr.offset}")
            if result.stack_size() > 0:
                top = result.peek()
                print(f"    Result pushed: tau={top.tau:#x}")
    return result

analyzer._transfer = traced_transfer

violations = analyzer.analyze()

print(f"\n=== Results ===")
print(f"Total violations: {len(violations)}")
print(f"Total iterations: {analyzer.total_iterations}")

for v in violations:
    print(f"  {v.bug_type} at line {v.line_number}: {v.sink_type.name}")
    print(f"    Reason: {v.reason[:100]}...")

# Check if we found command injection
cmd_violations = [v for v in violations if 'COMMAND' in v.sink_type.name]
print(f"\nCommand injection violations: {len(cmd_violations)}")
