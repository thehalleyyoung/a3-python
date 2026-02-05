#!/usr/bin/env python3
import dis

def conditional_list(flag):
    if flag:
        return [1, 2, 3, 4, 5]
    else:
        return [1, 2]

def access_index_1():
    x = conditional_list(True)
    return x[1]

print("Detailed bytecode:")
for instr in dis.get_instructions(access_index_1):
    print(f"{instr.offset:4d} {instr.opname:20s} {instr.arg} ({instr.argval})")
