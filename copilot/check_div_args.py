"""Get all division-related BINARY_OP args."""
import dis

# Check augmented division ops
aug_ops = [
    ("def f(x, y):\n    x /= y\n    return x", "/="),
    ("def f(x, y):\n    x //= y\n    return x", "//="),
    ("def f(x, y):\n    x %= y\n    return x", "%="),
]

print("=== Augmented division ops ===")
for src, name in aug_ops:
    code = compile(src, '<test>', 'exec')
    for c in code.co_consts:
        if hasattr(c, 'co_name') and c.co_name == 'f':
            for instr in dis.get_instructions(c):
                if instr.opname == 'BINARY_OP':
                    print(f"  BINARY_OP arg={instr.arg:3d}  argrepr={instr.argrepr:10s}  ({name})")

# Print the correct set
print()
print("=== Correct DIVISION_BINARY_OPS for this Python ===")
division_args = set()
test_ops = [
    ("def f(x, y):\n    return x / y", "/"),
    ("def f(x, y):\n    return x // y", "//"),
    ("def f(x, y):\n    return x % y", "%"),
]
for src, name in test_ops:
    code = compile(src, '<test>', 'exec')
    for c in code.co_consts:
        if hasattr(c, 'co_name') and c.co_name == 'f':
            for instr in dis.get_instructions(c):
                if instr.opname == 'BINARY_OP':
                    division_args.add(instr.arg)
                    print(f"  {name:5s} -> BINARY_OP arg={instr.arg}")

for src, name in aug_ops:
    code = compile(src, '<test>', 'exec')
    for c in code.co_consts:
        if hasattr(c, 'co_name') and c.co_name == 'f':
            for instr in dis.get_instructions(c):
                if instr.opname == 'BINARY_OP':
                    division_args.add(instr.arg)
                    print(f"  {name:5s} -> BINARY_OP arg={instr.arg}")

print(f"\n  DIVISION_BINARY_OPS = {division_args}")
