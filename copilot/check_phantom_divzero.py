"""Check if phantom DIV_ZERO functions actually have division bytecode."""
import dis

def find_code(co, name):
    results = []
    if co.co_name == name:
        results.append(co)
    for c in co.co_consts:
        if hasattr(c, 'co_name'):
            results.extend(find_code(c, name))
    return results

files_and_funcs = [
    ('external_tools/DeepSpeed/deepspeed/runtime/zero/partitioned_param_profiler.py', 'increment'),
    ('external_tools/DeepSpeed/deepspeed/autotuning/scheduler.py', 'status'),
    ('external_tools/DeepSpeed/deepspeed/runtime/engine.py', 'print_forward_breakdown'),
    ('external_tools/DeepSpeed/deepspeed/runtime/swap_tensor/optimizer_utils.py', 'write_unswapped_gradients'),
]

for filepath, fn_name in files_and_funcs:
    try:
        with open(filepath) as f:
            src = f.read()
        code = compile(src, filepath, 'exec')
        codes = find_code(code, fn_name)
        for c in codes:
            print(f'=== {c.co_qualname} ===')
            has_div = False
            for instr in dis.get_instructions(c):
                if instr.opname == 'BINARY_OP' and isinstance(instr.arg, int) and instr.arg in {11, 12, 13}:
                    has_div = True
                    print(f'  ** DIVISION at offset {instr.offset}: BINARY_OP {instr.arg} ({instr.argrepr})')
            if not has_div:
                print('  NO DIVISION FOUND')
            print()
    except Exception as e:
        print(f'Error with {filepath}: {e}')
