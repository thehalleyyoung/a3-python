#!/usr/bin/env python
"""Debug script for SOTA analyzer."""

from pyfromscratch.semantics.sota_intraprocedural import SOTAIntraproceduralAnalyzer, AbstractState
from pyfromscratch.contracts.security_lattice import is_security_sink, get_sink_contract
from pyfromscratch.z3model.taint_lattice import TaintLabel, SourceType
import types
import dis

source = '''
def test_func(user_input):
    lst = [user_input]
    x = lst[0]
    eval(x)
'''
code = compile(source, '<test>', 'exec')
func_code = None
for const in code.co_consts:
    if isinstance(const, types.CodeType) and const.co_name == 'test_func':
        func_code = const
        break

print("Bytecode:")
dis.dis(func_code)
print()

# Create analyzer and manually step through
analyzer = SOTAIntraproceduralAnalyzer(func_code, 'test_func', '<test>', verbose=True)

# Create entry state with tainted parameter
entry_state = AbstractState()
tainted = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, 'user_input')
entry_state.set_local(0, tainted)
print(f'Entry state: local 0 has tau={bin(entry_state.get_local(0).tau)}')

# Get the block
block = analyzer.cfg.blocks[0]

# Step through each instruction manually
print()
print('Manual stepping:')
for instr in block.instructions:
    print(f'Before {instr.opname} (arg={instr.arg}, argval={instr.argval}):')
    print(f'  Stack: {[("tau=" + bin(s.tau)) for s in entry_state.stack]}')
    print(f'  Locals: {[(k, "tau=" + bin(v.tau)) for k, v in entry_state.locals.items()]}')
    
    entry_state = analyzer._transfer(instr, entry_state)
    print(f'After {instr.opname}:')
    print(f'  Stack: {[("tau=" + bin(s.tau)) for s in entry_state.stack]}')
    print()

print(f'Violations found: {len(analyzer.violations)}')
for v in analyzer.violations:
    print(f'  {v}')
