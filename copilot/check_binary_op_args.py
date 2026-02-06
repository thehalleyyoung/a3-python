"""Check actual BINARY_OP arg values for different operations."""
import dis
import sys

print(f"Python version: {sys.version}")
print()

# Test what BINARY_OP args correspond to what
test_code = """
a = x + y
b = x - y
c = x * y
d = x / y
e = x // y
f = x % y
g = x ** y
h = x & y
i = x | y
j = x ^ y
k = x >> y
l = x << y
m = x @ y
n = x += 1
"""

# Simpler: just compile small expressions and check
ops = [
    ('x + y', 'add'),
    ('x - y', 'sub'),
    ('x * y', 'mul'),
    ('x / y', 'truediv'),
    ('x // y', 'floordiv'),
    ('x % y', 'mod'),
    ('x ** y', 'pow'),
    ('x & y', 'and'),
    ('x | y', 'or'),
    ('x ^ y', 'xor'),
    ('x >> y', 'rshift'),
    ('x << y', 'lshift'),
    ('x @ y', 'matmul'),
]

for expr, name in ops:
    func_code = f"def f(x, y):\n    return {expr}"
    code = compile(func_code, '<test>', 'exec')
    # Get the function code object
    for c in code.co_consts:
        if hasattr(c, 'co_name') and c.co_name == 'f':
            for instr in dis.get_instructions(c):
                if instr.opname == 'BINARY_OP':
                    print(f"  BINARY_OP arg={instr.arg:3d}  argrepr={instr.argrepr:10s}  operation={name}")

print()
# Also check augmented assignment
aug_code = "def f(x, y):\n    x += y\n    return x"
code = compile(aug_code, '<test>', 'exec')
for c in code.co_consts:
    if hasattr(c, 'co_name') and c.co_name == 'f':
        for instr in dis.get_instructions(c):
            if instr.opname == 'BINARY_OP':
                print(f"  BINARY_OP arg={instr.arg:3d}  argrepr={instr.argrepr:10s}  operation=iadd (+=)")

aug_code2 = "def f(x, y):\n    x -= y\n    return x"
code2 = compile(aug_code2, '<test>', 'exec')
for c in code2.co_consts:
    if hasattr(c, 'co_name') and c.co_name == 'f':
        for instr in dis.get_instructions(c):
            if instr.opname == 'BINARY_OP':
                print(f"  BINARY_OP arg={instr.arg:3d}  argrepr={instr.argrepr:10s}  operation=isub (-=)")

aug_code3 = "def f(x, y):\n    x /= y\n    return x"
code3 = compile(aug_code3, '<test>', 'exec')
for c in code3.co_consts:
    if hasattr(c, 'co_name') and c.co_name == 'f':
        for instr in dis.get_instructions(c):
            if instr.opname == 'BINARY_OP':
                print(f"  BINARY_OP arg={instr.arg:3d}  argrepr={instr.argrepr:10s}  operation=itruediv (/=)")
