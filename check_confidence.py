#!/usr/bin/env python3
"""Check bug confidence levels."""
import sys
sys.path.insert(0, '.')
from pyfromscratch.semantics.bytecode_summaries import BytecodeAbstractInterpreter

# Test on a Qlib file
filepath = 'external_tools/Qlib/qlib/utils/__init__.py'
with open(filepath) as f:
    source = f.read()
code = compile(source, filepath, 'exec')

# Find get_period_offset function
def find_func(code_obj, name):
    for const in code_obj.co_consts:
        if hasattr(const, 'co_name'):
            if const.co_name == name:
                return const
            found = find_func(const, name)
            if found:
                return found
    return None

func_code = find_func(code, 'get_period_offset')
if func_code:
    interp = BytecodeAbstractInterpreter(func_code, 'get_period_offset', 'get_period_offset')
    summary = interp.analyze()
    print(f'All bugs: {len(summary.potential_bugs)}')
    for bug in summary.potential_bugs:
        print(f'  {bug.bug_type} line {bug.line_number}: conf={bug.confidence:.2f}, guarded={bug.is_guarded}, sources={bug.param_sources}')
