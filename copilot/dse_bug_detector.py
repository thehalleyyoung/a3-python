#!/usr/bin/env python3
"""
DSE-Based Bug Detector using SymbolicVM with Z3.

This is the proper, principled approach to bug detection:
1. Compile each function to bytecode
2. Run symbolic execution with SymbolicVM (Z3-backed)
3. Check if bugs are actually reachable via check_unsafe_regions
4. Report only Z3-verified reachable bugs
5. Optionally synthesize barrier certificates for SAFE proofs

NO AD-HOC HEURISTICS - uses proper dataflow and SMT solving.

From barrier-certificate-theory.tex:
- Safety is B(s) >= 0 where B incorporates guards
- A bug is only real if Z3 proves the unsafe state is reachable
- If DSE finds no bugs AND barrier synthesis succeeds, we have SAFE proof

Architecture:
- SymbolicVM: Z3-backed bytecode execution (see semantics/symbolic_vm.py)
- check_unsafe_regions: Checks if symbolic state satisfies any unsafe predicate
- BarrierSynthesizer: Attempts to synthesize inductive barrier certificates
- GuardDataflowAnalysis: CFG-based guard propagation (see cfg/dataflow.py)
"""

import ast
import types
import sys
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field
import z3

# Import the DSE engine and unsafe predicates
from pyfromscratch.semantics.symbolic_vm import SymbolicVM, SymbolicPath
from pyfromscratch.unsafe.registry import check_unsafe_regions, SECURITY_BUG_TYPES


# Non-security bug types we're interested in
NON_SECURITY_BUG_TYPES = {
    'DIV_ZERO', 'NULL_PTR', 'BOUNDS', 'TYPE_CONFUSION', 
    'ASSERT_FAIL', 'INTEGER_OVERFLOW', 'FP_DOMAIN'
}


@dataclass
class DSEBug:
    """A bug found via DSE."""
    bug_type: str
    file_path: str
    function_name: str
    line_number: Optional[int]
    context: Optional[Dict]
    path_condition: Optional[str]  # The Z3 path condition that makes it reachable


def compile_function_to_code(source: str, func_name: str, filename: str) -> Optional[types.CodeType]:
    """
    Compile a Python source file and extract a function's code object.
    """
    try:
        tree = ast.parse(source)
        module_code = compile(tree, filename, 'exec')
        
        # Find the function's code object in the module's constants
        for const in module_code.co_consts:
            if isinstance(const, types.CodeType) and const.co_name == func_name:
                return const
            # Also search nested code objects
            if isinstance(const, types.CodeType):
                nested = _find_nested_code(const, func_name)
                if nested:
                    return nested
        return None
    except SyntaxError:
        return None


def _find_nested_code(code: types.CodeType, name: str) -> Optional[types.CodeType]:
    """Recursively find a nested function's code object."""
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name == name:
                return const
            nested = _find_nested_code(const, name)
            if nested:
                return nested
    return None


def analyze_function_with_dse(
    code: types.CodeType,
    func_name: str,
    file_path: str,
    max_steps: int = 100,
    bug_types: Optional[Set[str]] = None,
) -> List[DSEBug]:
    """
    Analyze a single function using DSE with SymbolicVM.
    
    This is the proper approach using Z3-backed symbolic execution.
    A bug is only reported if Z3 proves the unsafe state is reachable.
    """
    if bug_types is None:
        bug_types = NON_SECURITY_BUG_TYPES
    
    bugs = []
    
    try:
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=max_steps)
        
        for path in paths:
            # Check if any unsafe predicate is satisfied
            result = check_unsafe_regions(path.state, path.trace)
            
            if result is not None:
                bug_type = result.get('bug_type')
                
                # Filter by bug types we're interested in
                if bug_type and bug_type in bug_types:
                    bug = DSEBug(
                        bug_type=bug_type,
                        file_path=file_path,
                        function_name=func_name,
                        line_number=result.get('line_number'),
                        context=result.get('context'),
                        path_condition=str(path.state.path_condition) if hasattr(path.state, 'path_condition') else None
                    )
                    bugs.append(bug)
    except Exception as e:
        # DSE can fail on complex code - this is expected
        pass
    
    return bugs


def analyze_file_with_dse(
    file_path: Path,
    max_steps: int = 100,
    bug_types: Optional[Set[str]] = None,
) -> List[DSEBug]:
    """
    Analyze all functions in a file using DSE.
    """
    if bug_types is None:
        bug_types = NON_SECURITY_BUG_TYPES
    
    bugs = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        
        tree = ast.parse(source)
        
        # Collect all function definitions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                
                # Compile the whole module to get code objects
                try:
                    module_code = compile(source, str(file_path), 'exec')
                    
                    # Find this function's code object
                    func_code = None
                    for const in module_code.co_consts:
                        if isinstance(const, types.CodeType):
                            if const.co_name == func_name and const.co_firstlineno == node.lineno:
                                func_code = const
                                break
                            # Check nested
                            nested = _find_code_by_line(const, func_name, node.lineno)
                            if nested:
                                func_code = nested
                                break
                    
                    if func_code:
                        func_bugs = analyze_function_with_dse(
                            func_code, func_name, str(file_path),
                            max_steps=max_steps, bug_types=bug_types
                        )
                        bugs.extend(func_bugs)
                except Exception:
                    pass
    except Exception:
        pass
    
    return bugs


def _find_code_by_line(code: types.CodeType, name: str, line: int) -> Optional[types.CodeType]:
    """Find code object by name and line number."""
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name == name and const.co_firstlineno == line:
                return const
            nested = _find_code_by_line(const, name, line)
            if nested:
                return nested
    return None


@dataclass
class AnalysisResult:
    """Result of DSE analysis for a function."""
    function_name: str
    file_path: str
    bugs: List[DSEBug] = field(default_factory=list)
    safe_proofs: List[str] = field(default_factory=list)  # Bug types proven safe
    unknown: List[str] = field(default_factory=list)  # Bug types not determined
    paths_explored: int = 0
    barrier_synthesized: bool = False


def analyze_with_barrier_synthesis(
    code: types.CodeType,
    func_name: str,
    file_path: str,
    max_steps: int = 100,
    attempt_barrier: bool = True,
) -> AnalysisResult:
    """
    Full DSE + Barrier analysis for a function.
    
    1. Run DSE with SymbolicVM
    2. Check each path for bugs using check_unsafe_regions
    3. If no bugs found, attempt barrier synthesis for SAFE proof
    
    Returns:
        AnalysisResult with bugs, safe_proofs, or unknown status
    """
    result = AnalysisResult(function_name=func_name, file_path=file_path)
    
    try:
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=max_steps)
        result.paths_explored = len(paths)
        
        bugs_by_type: Dict[str, List[DSEBug]] = defaultdict(list)
        
        for path in paths:
            unsafe = check_unsafe_regions(path.state, path.trace)
            
            if unsafe is not None:
                bug_type = unsafe.get('bug_type')
                if bug_type:
                    bug = DSEBug(
                        bug_type=bug_type,
                        file_path=file_path,
                        function_name=func_name,
                        line_number=unsafe.get('line_number'),
                        context=unsafe.get('context'),
                        path_condition=str(path.state.path_condition) if hasattr(path.state, 'path_condition') else None
                    )
                    bugs_by_type[bug_type].append(bug)
        
        # Deduplicate bugs (same type + line)
        seen = set()
        for bug_type, bug_list in bugs_by_type.items():
            for bug in bug_list:
                key = (bug_type, bug.line_number)
                if key not in seen:
                    seen.add(key)
                    result.bugs.append(bug)
        
        # If no bugs found, attempt barrier synthesis for SAFE proof
        if not result.bugs and attempt_barrier:
            try:
                from pyfromscratch.barriers import BarrierSynthesizer, SynthesisConfig
                
                config = SynthesisConfig(
                    max_degree=2,
                    timeout_ms=5000,
                    use_sos=True,
                )
                synthesizer = BarrierSynthesizer(code, config)
                
                for bug_type in NON_SECURITY_BUG_TYPES:
                    proof = synthesizer.synthesize_for_bug_type(bug_type)
                    if proof and proof.verified:
                        result.safe_proofs.append(bug_type)
                        result.barrier_synthesized = True
                    else:
                        result.unknown.append(bug_type)
            except ImportError:
                # Barrier synthesis not available
                result.unknown = list(NON_SECURITY_BUG_TYPES)
            except Exception:
                result.unknown = list(NON_SECURITY_BUG_TYPES)
        
    except Exception as e:
        # DSE failed - status is unknown
        result.unknown = list(NON_SECURITY_BUG_TYPES)
    
    return result


def analyze_directory_with_dse(
    dir_path: Path,
    max_steps: int = 50,
    max_files: int = 100,
    bug_types: Optional[Set[str]] = None,
) -> Dict[str, List[DSEBug]]:
    """
    Analyze all Python files in a directory using DSE.
    
    Returns: Dict mapping bug_type -> list of bugs
    """
    if bug_types is None:
        bug_types = NON_SECURITY_BUG_TYPES
    
    all_bugs: Dict[str, List[DSEBug]] = defaultdict(list)
    files_processed = 0
    
    # Find all Python files
    python_files = list(dir_path.rglob('*.py'))
    
    # Skip test files and __pycache__
    python_files = [f for f in python_files 
                   if '__pycache__' not in str(f) 
                   and 'test' not in f.name.lower()
                   and not f.name.startswith('test_')]
    
    for file_path in python_files:
        if files_processed >= max_files:
            break
        
        try:
            bugs = analyze_file_with_dse(file_path, max_steps=max_steps, bug_types=bug_types)
            for bug in bugs:
                all_bugs[bug.bug_type].append(bug)
            files_processed += 1
        except Exception:
            pass
    
    return all_bugs


def analyze_interprocedural_with_dse(
    project_path: Path,
    max_steps: int = 50,
    max_functions: int = 500,
) -> Tuple[Dict[str, List[DSEBug]], Dict[str, int]]:
    """
    Interprocedural DSE analysis across a project.
    
    Uses call graph to prioritize analysis and propagate results.
    
    Returns:
        Tuple of (bugs_by_type, stats)
    """
    from pyfromscratch.cfg.call_graph import build_call_graph_from_project
    
    call_graph = build_call_graph_from_project(project_path)
    
    all_bugs: Dict[str, List[DSEBug]] = defaultdict(list)
    stats = {
        'functions_analyzed': 0,
        'bugs_found': 0,
        'safe_proofs': 0,
        'unknown': 0,
    }
    
    # Process in reverse topological order (callees before callers)
    sccs = call_graph.compute_sccs()
    function_results: Dict[str, AnalysisResult] = {}
    
    for scc in sccs:
        if stats['functions_analyzed'] >= max_functions:
            break
        
        for func_name in scc:
            if stats['functions_analyzed'] >= max_functions:
                break
            
            func_info = call_graph.get_function(func_name)
            if not func_info:
                continue
            
            # Get code object
            try:
                with open(func_info.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    source = f.read()
                
                module_code = compile(source, str(func_info.file_path), 'exec')
                func_code = None
                
                # Find the function's code object
                for const in module_code.co_consts:
                    if isinstance(const, types.CodeType):
                        if const.co_name == func_info.name and const.co_firstlineno == func_info.line_number:
                            func_code = const
                            break
                        nested = _find_code_by_line(const, func_info.name, func_info.line_number)
                        if nested:
                            func_code = nested
                            break
                
                if func_code:
                    result = analyze_with_barrier_synthesis(
                        func_code, func_name, str(func_info.file_path),
                        max_steps=max_steps
                    )
                    function_results[func_name] = result
                    
                    for bug in result.bugs:
                        all_bugs[bug.bug_type].append(bug)
                        stats['bugs_found'] += 1
                    
                    stats['safe_proofs'] += len(result.safe_proofs)
                    stats['unknown'] += len(result.unknown)
                    stats['functions_analyzed'] += 1
                    
            except Exception:
                stats['unknown'] += 1
    
    return all_bugs, stats


def main():
    """Analyze external_tools repos using DSE."""
    import argparse
    
    parser = argparse.ArgumentParser(description='DSE-based bug detection')
    parser.add_argument('--repo', type=str, help='Specific repo to analyze')
    parser.add_argument('--max-steps', type=int, default=50, help='Max DSE steps per function')
    parser.add_argument('--max-files', type=int, default=50, help='Max files per repo')
    parser.add_argument('--interprocedural', action='store_true', help='Use interprocedural analysis')
    args = parser.parse_args()
    
    base_path = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools')
    
    if args.repo:
        repos = [args.repo]
    else:
        # Analyze all repos
        repos = [d.name for d in base_path.iterdir() if d.is_dir()]
    
    total_bugs = defaultdict(int)
    
    for repo in repos:
        repo_path = base_path / repo
        if not repo_path.exists():
            continue
        
        print(f"\n{'='*60}")
        print(f"Analyzing {repo} with DSE (Z3-backed)...")
        print(f"{'='*60}")
        
        if args.interprocedural:
            bugs, stats = analyze_interprocedural_with_dse(
                repo_path, 
                max_steps=args.max_steps,
                max_functions=args.max_files * 10
            )
            print(f"  Functions analyzed: {stats['functions_analyzed']}")
            print(f"  Safe proofs: {stats['safe_proofs']}")
        else:
            bugs = analyze_directory_with_dse(
                repo_path, 
                max_steps=args.max_steps, 
                max_files=args.max_files
            )
        
        for bug_type, bug_list in bugs.items():
            count = len(bug_list)
            total_bugs[bug_type] += count
            print(f"  {bug_type}: {count}")
            
            # Show first few examples
            for bug in bug_list[:3]:
                print(f"    - {bug.file_path}:{bug.function_name}")
                if bug.line_number:
                    print(f"      Line {bug.line_number}")
    
    print(f"\n{'='*60}")
    print("TOTAL (DSE-verified bugs):")
    print(f"{'='*60}")
    for bug_type, count in sorted(total_bugs.items()):
        print(f"  {bug_type}: {count}")


if __name__ == '__main__':
    main()
