"""Validate the new DSE-confirmed true positives, especially DIV_ZERO ones."""
import os

base = 'external_tools/DeepSpeed'

checks = [
    ('deepspeed/inference/v2/inference_utils.py', 'ceil_div', 'DIV_ZERO'),
    ('deepspeed/inference/v2/model_implementations/llama_v2/model.py', 'head_size', 'DIV_ZERO'),
    ('deepspeed/utils/groups.py', '_ensure_divisibility', 'DIV_ZERO'),
    ('deepspeed/utils/timer.py', '_is_report_boundary', 'DIV_ZERO'),
    ('deepspeed/runtime/pipe/schedule.py', '_buffer_idx', 'DIV_ZERO'),
    ('deepspeed/runtime/swap_tensor/partitioned_param_swapper.py', '_is_io_aligned', 'DIV_ZERO'),
    ('deepspeed/io/fast_file_writer.py', 'write', 'DIV_ZERO - FastFileWriter'),
    ('deepspeed/compression/helper.py', 'recursive_getattr', 'NULL_PTR'),
]

for filepath, fn_name, bug_type in checks:
    full_path = os.path.join(base, filepath)
    if not os.path.exists(full_path):
        print(f'FILE NOT FOUND: {full_path}')
        continue
    
    with open(full_path) as f:
        lines = f.readlines()
    
    # Find the function
    in_func = False
    func_lines = []
    indent = 0
    for i, line in enumerate(lines, 1):
        stripped = line.rstrip()
        if f'def {fn_name}' in stripped:
            in_func = True
            indent = len(line) - len(line.lstrip())
            func_lines = [(i, stripped)]
            continue
        if in_func:
            if stripped and not stripped.startswith('#'):
                cur_indent = len(line) - len(line.lstrip())
                if cur_indent <= indent and stripped and not stripped.startswith(')'):
                    break
            func_lines.append((i, stripped))
    
    print(f'=== {bug_type}: {filepath}::{fn_name} ===')
    for lineno, text in func_lines[:25]:
        print(f'  {lineno:4d}: {text}')
    print()
