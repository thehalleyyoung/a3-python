#!/usr/bin/env python3
"""Show bytecode around Popen call"""
import dis, types

with open('external_tools/pygoat/introduction/views.py', 'r') as f:
    source = f.read()
    
code = compile(source, 'views.py', 'exec')

for const in code.co_consts:
    if isinstance(const, types.CodeType) and const.co_name == 'cmd_lab':
        instrs = list(dis.get_instructions(const))
        # Find CALL_KW at offset 446 and show surrounding context
        for i, instr in enumerate(instrs):
            if instr.offset >= 340 and instr.offset <= 460:
                print(f'{instr.offset:3d} {instr.opname:25s} {repr(instr.argval)}')
