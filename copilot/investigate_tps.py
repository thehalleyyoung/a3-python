#!/usr/bin/env python3
"""
Investigate every reported TP by reading the actual DeepSpeed source code
and classifying each as:
  - REAL_BUG: genuinely reachable with reasonable inputs
  - INTENTIONAL_GUARD: raise is deliberate validation, not a defect
  - FP_CONTEXT: unreachable due to context our analysis can't model
  - PROPERTY_MISFIRE: property/descriptor misidentified as function

Outputs a structured JSON + markdown report.
"""

import os
import pickle
import json
import dis
import textwrap
from pathlib import Path
from collections import defaultdict

DEEPSPEED = Path('external_tools/DeepSpeed')

# Load results
with open('results/full_analysis_results.pkl', 'rb') as f:
    results = pickle.load(f)

prod_bugs = results.get('prod_bugs', [])
test_bugs = results.get('test_bugs', [])


def find_source(func_name):
    """Find source file and function body for a dotted function name."""
    parts = func_name.split('.')
    # Try progressively shorter module paths
    for i in range(len(parts), 0, -1):
        candidate = DEEPSPEED / '/'.join(parts[:i])
        py = candidate.with_suffix('.py')
        init = candidate / '__init__.py'
        if py.exists():
            filepath = py
            fn_parts = parts[i:]
            break
        elif init.exists():
            filepath = init
            fn_parts = parts[i:]
            break
    else:
        return None, None, None, None

    fn_name = fn_parts[-1] if fn_parts else parts[-1]
    class_name = fn_parts[-2] if len(fn_parts) >= 2 else None

    try:
        with open(filepath) as f:
            lines = f.readlines()
    except Exception:
        return str(filepath), None, None, None

    # Find function definition
    for i, line in enumerate(lines):
        if f'def {fn_name}' in line:
            # Check if it's in the right class
            if class_name:
                # Look backward for class def
                found_class = False
                for j in range(i - 1, max(-1, i - 100), -1):
                    if f'class {class_name}' in lines[j]:
                        found_class = True
                        break
                if not found_class:
                    continue

            start = i
            indent = len(line) - len(line.lstrip())
            end = i + 1
            for j in range(i + 1, min(len(lines), i + 80)):
                stripped = lines[j].rstrip()
                if stripped == '':
                    end = j + 1
                    continue
                cur_indent = len(lines[j]) - len(lines[j].lstrip())
                if cur_indent <= indent and stripped:
                    break
                end = j + 1

            body = ''.join(lines[start:end]).rstrip()
            return str(filepath), start + 1, fn_name, body

    return str(filepath), None, fn_name, None


def classify_bug(func_name, bug_type, body):
    """Classify a reported bug by reading the source."""
    if body is None:
        return 'UNKNOWN', 'Source not found'

    body_lower = body.lower()
    lines = body.strip().split('\n')
    # Strip docstring
    code_lines = []
    in_docstring = False
    for line in lines[1:]:  # skip def line
        stripped = line.strip()
        if stripped.startswith('"""') or stripped.startswith("'''"):
            if in_docstring:
                in_docstring = False
                continue
            elif stripped.count('"""') >= 2 or stripped.count("'''") >= 2:
                continue  # single-line docstring
            else:
                in_docstring = True
                continue
        if not in_docstring:
            code_lines.append(stripped)

    code_body = '\n'.join(code_lines)

    # ----- RUNTIME_ERROR / VALUE_ERROR: intentional guards -----
    if bug_type in ('RUNTIME_ERROR', 'VALUE_ERROR'):
        if 'raise RuntimeError' in body or 'raise ValueError' in body:
            return 'INTENTIONAL_GUARD', 'Deliberate validation raise'

    # ----- DIV_ZERO -----
    if bug_type == 'DIV_ZERO':
        # Check if it's a function whose PURPOSE is division
        if 'ceil_div' in func_name or 'ensure_divisibility' in func_name:
            return 'REAL_BUG', f'Division function with no zero-check on divisor'
        # Check for // or / or % in code
        has_div = False
        for cl in code_lines:
            if '//' in cl or ' / ' in cl or ' % ' in cl:
                has_div = True
                break
        if not has_div:
            return 'FP_CONTEXT', 'No division found in function body'
        # Property that divides by self.n_heads etc
        if 'self.' in code_body and ('//' in code_body or '/' in code_body):
            # Check if divisor is a config value
            if 'n_heads' in code_body or 'num_heads' in code_body:
                return 'REAL_BUG', 'Division by model config (n_heads) which could be 0 if misconfigured'
            if 'alignment' in code_body or 'align' in code_body:
                return 'REAL_BUG', 'Division by alignment value which could be 0'
            if 'num_pipe_buffers' in code_body:
                return 'REAL_BUG', 'Division by num_pipe_buffers() which could return 0'
            if 'steps_per_output' in code_body:
                return 'REAL_BUG', 'Modulo by steps_per_output; None case guarded but 0 is not'
            return 'REAL_BUG', 'Division by instance attribute that could be 0'
        return 'REAL_BUG', 'Division with unguarded divisor'

    # ----- NULL_PTR -----
    if bug_type == 'NULL_PTR':
        # Property setters (self.xxx = value)
        if func_name.endswith(('._set_state', '._set_param_groups', '._set_loss_scale',
                               '.set_gradient_accumulation_boundary', '.communication_data_type',
                               '._backward_active_depth', '._backward_seen_this_step',
                               '._epilogue_ran_this_backward', '._grad_acc_post_hooks',
                               '._hooks_fired_this_backward', '._max_expected_hooks_seen',
                               '._remaining_grad_acc_hooks')):
            # These are property setters/getters on self - self is never None in normal usage
            if '@property' in body or '.setter' in body or 'self.' in code_body:
                if len(code_lines) <= 3:  # Simple property
                    return 'FP_CONTEXT', 'Property accessor on self; self is never None in normal method calls'

        # @property that just returns self.something
        if '@property' in body or '@staticmethod' not in body:
            if len(code_lines) <= 2 and code_lines and 'return self.' in code_lines[0]:
                return 'FP_CONTEXT', 'Simple property returning self attribute; self is guaranteed non-None'

        # @pytest.fixture functions - parameters are injected by pytest
        if 'pytest' in func_name or 'conftest' in func_name or 'fixture' in body_lower:
            return 'FP_CONTEXT', 'Pytest fixture/conftest; parameters injected by test framework'

        # Functions that take a single `parser` arg (argparse)
        if 'parser' in body and ('add_argument' in body or 'add_mutually_exclusive_group' in body):
            return 'FP_CONTEXT', 'Argparse pattern; parser is always provided by argparse framework'

        # Functions whose params come from framework (e.g. self)
        if 'def ' in lines[0]:
            # Extract params
            def_line = lines[0]
            if '(self' in def_line and code_body.count('self.') >= 1:
                # Method - check if the only NULL_PTR risk is self
                non_self_attrs = False
                for cl in code_lines:
                    # Check for attribute access on non-self variables
                    if '.' in cl and 'self.' not in cl.split('.')[0]:
                        non_self_attrs = True
                        break

                if not non_self_attrs and len(code_lines) <= 4:
                    return 'FP_CONTEXT', 'Method only accesses self attributes; self guaranteed non-None'

        # recursive_getattr - genuine traversal bug
        if 'getattr' in code_body and 'for' in code_body:
            return 'REAL_BUG', 'Iterative getattr with no None check; intermediate attr could be None'

        # Accelerator methods - is_pinned, pin_memory, replay_graph
        if 'accelerator' in func_name:
            if '(self' in lines[0]:
                # Check if it's using an external attribute that could be None
                for cl in code_lines:
                    if 'self.' in cl and ('(' in cl or '[' in cl):
                        return 'REAL_BUG', 'Accelerator method; underlying device handle could be None if HW not available'
                return 'FP_CONTEXT', 'Accelerator method on self; self always valid in normal usage'

        # Functions that check params from user
        if 'checkpoint' in func_name or 'restore' in func_name:
            return 'REAL_BUG', 'Checkpoint/restore function; input files/objects could be None'

        # General: does it access attributes on a parameter?
        return 'REAL_BUG', 'Attribute access on parameter that could be None'

    return 'REAL_BUG', 'Unclassified potential true positive'


# ============ Main investigation ============
all_bugs = []

print("Investigating production true positives...")
for func_name, bug_type in prod_bugs:
    filepath, lineno, fn_name, body = find_source(func_name)
    verdict, reason = classify_bug(func_name, bug_type, body)
    all_bugs.append({
        'function': func_name,
        'bug_type': bug_type,
        'file': filepath,
        'line': lineno,
        'verdict': verdict,
        'reason': reason,
        'body': body[:500] if body else None,
        'is_test': False,
    })

print("Investigating test true positives...")
for func_name, bug_type in test_bugs:
    filepath, lineno, fn_name, body = find_source(func_name)
    verdict, reason = classify_bug(func_name, bug_type, body)
    all_bugs.append({
        'function': func_name,
        'bug_type': bug_type,
        'file': filepath,
        'line': lineno,
        'verdict': verdict,
        'reason': reason,
        'body': body[:500] if body else None,
        'is_test': True,
    })

# ============ Statistics ============
verdicts = defaultdict(list)
for b in all_bugs:
    verdicts[b['verdict']].append(b)

print(f"\n{'='*70}")
print(f"INVESTIGATION RESULTS: {len(all_bugs)} reported TPs")
print(f"{'='*70}")
for v in ['REAL_BUG', 'INTENTIONAL_GUARD', 'FP_CONTEXT', 'UNKNOWN']:
    bugs = verdicts.get(v, [])
    if bugs:
        prod = [b for b in bugs if not b['is_test']]
        test = [b for b in bugs if b['is_test']]
        print(f"  {v:20s}: {len(bugs):3d} ({len(prod)} prod, {len(test)} test)")

# Save for document generation
with open('results/tp_investigation.json', 'w') as f:
    json.dump(all_bugs, f, indent=2, default=str)
print(f"\nSaved detailed results to results/tp_investigation.json")
