"""Check actual source code of remaining NULL_PTR bugs to see if they have guards."""
import pickle, sys, ast
from pathlib import Path
sys.path.insert(0, '.')

from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

with open('results/deepspeed_crash_summaries_v2.pkl', 'rb') as f:
    summaries = pickle.load(f)

engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)

# Collect remaining
remaining = []
for func_name, summary in summaries.items():
    gc = getattr(summary, 'guard_counts', {})
    gb = getattr(summary, 'guarded_bugs', set())
    for bug_type, (guarded_count, total_count) in gc.items():
        if bug_type in gb:
            continue
        is_safe, cert = engine.verify_via_deep_barriers(bug_type, '<v>', summary)
        if not is_safe:
            remaining.append((func_name, bug_type, summary))

# Look at 5 specific NULL_PTR functions
null_remaining = [(n, bt, s) for n, bt, s in remaining if bt == 'NULL_PTR']
print(f"Total NULL_PTR remaining: {len(null_remaining)}")

# Try to find their source files
deepspeed_root = Path('external_tools/DeepSpeed')
for func_name, bt, s in null_remaining[:8]:
    # Convert function name to file path guess
    parts = func_name.split('.')
    # Try to find the module file
    module_path = None
    for i in range(len(parts), 0, -1):
        candidate = deepspeed_root / ('/'.join(parts[:i]) + '.py')
        if candidate.exists():
            module_path = candidate
            break
        candidate = deepspeed_root / '/'.join(parts[:i]) / '__init__.py'
        if candidate.exists():
            module_path = candidate
            break

    print(f"\n{'='*60}")
    print(f"Function: {func_name}")
    print(f"  guard_counts: {s.guard_counts}")
    
    if module_path:
        print(f"  Source: {module_path}")
        # Find the function in the source
        try:
            source = module_path.read_text()
            tree = ast.parse(source)
            func_short = parts[-1]
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == func_short:
                        # Get the function source
                        lines = source.split('\n')
                        start = node.lineno - 1
                        end = node.end_lineno if hasattr(node, 'end_lineno') and node.end_lineno else min(start + 30, len(lines))
                        func_source = '\n'.join(lines[start:end])
                        # Truncate if too long
                        if len(func_source) > 800:
                            func_source = func_source[:800] + '\n    ...'
                        print(f"  Source ({end-start} lines):")
                        print(f"  {'-'*40}")
                        for line in func_source.split('\n')[:25]:
                            print(f"    {line}")
                        break
        except Exception as e:
            print(f"  Error reading source: {e}")
    else:
        print(f"  Source: NOT FOUND")
