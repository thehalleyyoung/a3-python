#!/usr/bin/env python3
"""
Fast analysis with reduced scope for quick iteration.
"""
import os
import sys
import time
import traceback
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict

@dataclass
class FunctionResult:
    name: str
    file_path: str
    time_sec: float
    error: Optional[str] = None
    bugs: Dict[str, Tuple[int, int]] = field(default_factory=dict)  # (guarded, unguarded)

BUG_TYPES = ['NULL_PTR', 'BOUNDS', 'DIV_ZERO']

def analyze_function_safe(code, func_name: str, qualified_name: str) -> FunctionResult:
    """Analyze a single function with error handling."""
    from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryAnalyzer
    
    result = FunctionResult(name=func_name, file_path="", time_sec=0.0)
    start = time.time()
    
    try:
        # Skip very large functions
        if len(code.co_code) > 5000:
            result.error = "Skipped (too large)"
            result.time_sec = time.time() - start
            return result
        
        analyzer = BytecodeCrashSummaryAnalyzer(code, func_name, qualified_name)
        analyzer.analyze()
        summary = analyzer.summary
        
        for bug_type in BUG_TYPES:
            guarded, unguarded = summary.guard_counts.get(bug_type, (0, 0))
            result.bugs[bug_type] = (guarded, unguarded)
            
    except Exception as e:
        result.error = str(e)[:100]
    
    result.time_sec = time.time() - start
    return result

def analyze_file_safe(file_path: str) -> List[FunctionResult]:
    """Analyze all functions in a Python file."""
    import types
    
    results = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        
        compiled = compile(source, file_path, 'exec')
        
        def extract_code_objects(code, prefix=""):
            objs = []
            for const in code.co_consts:
                if isinstance(const, types.CodeType):
                    name = const.co_name
                    qualified = f"{prefix}.{name}" if prefix else name
                    if name not in ('<module>', '<listcomp>', '<dictcomp>', '<setcomp>', '<genexpr>'):
                        objs.append((const, name, qualified))
                    objs.extend(extract_code_objects(const, qualified))
            return objs
        
        code_objects = extract_code_objects(compiled)
        
        for code, name, qualified in code_objects:
            func_result = analyze_function_safe(code, name, qualified)
            func_result.file_path = file_path
            results.append(func_result)
            
    except SyntaxError:
        pass
    except Exception as e:
        pass
    
    return results

def find_python_files(repo_path: str, max_files: int = 30) -> List[str]:
    """Find Python files in a repository."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {
            '__pycache__', '.git', 'node_modules', 'venv', '.venv',
            'build', 'dist', '.tox', '.eggs', 'test', 'tests'
        }]
        
        for f in filenames:
            if f.endswith('.py') and not f.startswith('test_') and 'test' not in f.lower():
                files.append(os.path.join(root, f))
                if len(files) >= max_files:
                    return files
    return files

def main():
    """Main entry point."""
    external_tools = Path("/Users/halleyyoung/Documents/PythonFromScratch/external_tools")
    
    repos = ["django", "pygoat", "LightGBM", "FLAML"]
    
    print("="*70)
    print("FAST ANALYSIS - 6 repos, 30 files each")
    print("="*70)
    
    # Aggregate stats
    total_funcs = 0
    total_time = 0.0
    bugs_guarded: Dict[str, int] = defaultdict(int)
    bugs_unguarded: Dict[str, int] = defaultdict(int)
    slow_funcs: List[Tuple[str, str, float]] = []
    error_funcs: List[Tuple[str, str, str]] = []
    
    # Files with most bugs
    file_bugs: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    
    for repo_name in repos:
        repo_path = external_tools / repo_name
        if not repo_path.exists():
            continue
        
        print(f"\n{repo_name}:")
        files = find_python_files(str(repo_path), max_files=30)
        print(f"  {len(files)} files", end="", flush=True)
        
        repo_funcs = 0
        repo_time = 0.0
        
        for file_path in files:
            results = analyze_file_safe(file_path)
            for r in results:
                repo_funcs += 1
                repo_time += r.time_sec
                
                if r.error:
                    error_funcs.append((r.name, file_path, r.error))
                else:
                    if r.time_sec > 0.5:
                        slow_funcs.append((r.name, file_path, r.time_sec))
                    
                    for bug_type, (guarded, unguarded) in r.bugs.items():
                        bugs_guarded[bug_type] += guarded
                        bugs_unguarded[bug_type] += unguarded
                        if unguarded > 0:
                            rel = os.path.relpath(file_path, str(external_tools))
                            file_bugs[rel][bug_type] += unguarded
        
        total_funcs += repo_funcs
        total_time += repo_time
        print(f" -> {repo_funcs} functions in {repo_time:.1f}s")
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total functions: {total_funcs}")
    print(f"Total time: {total_time:.1f}s")
    print(f"Avg per function: {total_time/max(total_funcs,1)*1000:.1f}ms")
    print(f"Errors: {len(error_funcs)}")
    
    print(f"\n{'Bug Type':<15} {'Guarded':>10} {'Unguarded':>10} {'Total':>10} {'%FP Reduced':>12}")
    print("-"*57)
    
    total_g = 0
    total_u = 0
    for bug_type in BUG_TYPES:
        g = bugs_guarded[bug_type]
        u = bugs_unguarded[bug_type]
        total_g += g
        total_u += u
        t = g + u
        pct = 100*g/max(t, 1)
        print(f"{bug_type:<15} {g:>10} {u:>10} {t:>10} {pct:>11.1f}%")
    
    print("-"*57)
    t = total_g + total_u
    pct = 100*total_g/max(t, 1)
    print(f"{'TOTAL':<15} {total_g:>10} {total_u:>10} {t:>10} {pct:>11.1f}%")
    
    print(f"\nSlow functions (>{0.5}s):")
    slow_funcs.sort(key=lambda x: -x[2])
    for name, path, t in slow_funcs[:10]:
        rel = os.path.relpath(path, str(external_tools))
        print(f"  {t:.2f}s: {name} in {rel}")
    
    print(f"\nFiles with most unguarded bugs:")
    file_totals = [(p, sum(b.values()), b) for p, b in file_bugs.items()]
    file_totals.sort(key=lambda x: -x[1])
    for path, total, bugs in file_totals[:10]:
        bug_str = ", ".join(f"{k}:{v}" for k, v in bugs.items() if v > 0)
        print(f"  {total:>3} bugs: {path} ({bug_str})")
    
    print(f"\nSample errors:")
    for name, path, err in error_funcs[:5]:
        rel = os.path.relpath(path, str(external_tools))
        print(f"  {name}: {err[:60]}")

if __name__ == "__main__":
    main()
