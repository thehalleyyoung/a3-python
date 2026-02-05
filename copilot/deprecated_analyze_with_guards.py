#!/usr/bin/env python3
"""
Improved analysis with guard-based FP reduction.

Key insight from barrier certificate theory:
- Safety is B(s) >= 0 where B incorporates guards
- Guards are derived from control flow (dominance) and semantic facts
- A bug is only real if the unsafe state is reachable WITH guards = 0
"""

import ast
from pathlib import Path
from collections import defaultdict
from typing import Optional, Set, Dict, List
import re

class GuardTracker:
    """Track guards that dominate the current program point."""
    
    def __init__(self):
        self.nonnull_vars: Set[str] = set()  # Variables known non-None
        self.nonzero_vars: Set[str] = set()  # Variables known non-zero
        self.nonempty_vars: Set[str] = set()  # Containers known non-empty
        self.type_info: Dict[str, str] = {}  # Variable -> inferred type
        
    def copy(self):
        g = GuardTracker()
        g.nonnull_vars = self.nonnull_vars.copy()
        g.nonzero_vars = self.nonzero_vars.copy()
        g.nonempty_vars = self.nonempty_vars.copy()
        g.type_info = self.type_info.copy()
        return g

class ImprovedBugAnalyzer(ast.NodeVisitor):
    """
    Improved analyzer that reduces FPs using:
    1. Type inference (Path vs numeric)
    2. Semantic guarantees (self is non-None)
    3. Guard propagation (if x is not None: x.attr is safe)
    4. Pattern recognition (for i in range(len(x)): x[i] is safe)
    """
    
    # Modules/builtins known to never be None
    NEVER_NONE = {
        'self', 'cls', 'os', 'sys', 'np', 'pd', 'math', 'json', 're',
        'logging', 'datetime', 'collections', 'itertools', 'functools',
        'typing', 'pathlib', 'Path', 'io', 'struct', 'copy', 'pickle',
    }
    
    # Path-related names (use __truediv__, not numeric division)
    PATH_NAMES = {'path', 'dir', 'directory', 'folder', 'filepath', 'file_path', 
                  'base_path', 'root_path', 'output_path', 'input_path'}
    
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.bugs = {'div_zero': [], 'null_ptr': [], 'bounds': [], 'type_confusion': []}
        self.guards = GuardTracker()
        self.in_loop_with_enumerate = False
        self.loop_vars: Dict[str, str] = {}  # loop var -> container it iterates
        self.current_function: Optional[str] = None
        
    def analyze(self) -> dict:
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
            tree = ast.parse(source)
            self.visit(tree)
        except:
            pass
        return self.bugs
    
    def visit_FunctionDef(self, node):
        old_function = self.current_function
        self.current_function = node.name
        
        # 'self' is guaranteed non-None in methods
        old_guards = self.guards.copy()
        if node.args.args and node.args.args[0].arg == 'self':
            self.guards.nonnull_vars.add('self')
        if node.args.args and node.args.args[0].arg == 'cls':
            self.guards.nonnull_vars.add('cls')
            
        self.generic_visit(node)
        
        self.guards = old_guards
        self.current_function = old_function
    
    def _body_terminates(self, body: list) -> bool:
        """Check if a block always terminates (raise, return, continue, break)."""
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.If):
            if_terminates = self._body_terminates(last.body)
            else_terminates = self._body_terminates(last.orelse) if last.orelse else False
            return if_terminates and else_terminates
        return False
    
    def _extract_inverted_guards(self, test: ast.AST):
        """Extract guards from the OPPOSITE of a test (for early-return patterns)."""
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            # if x is None: raise -> x is NOT None after
            if isinstance(test.ops[0], ast.Is):
                if isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None:
                    if isinstance(test.left, ast.Name):
                        self.guards.nonnull_vars.add(test.left.id)
            # if x == 0: return -> x != 0 after
            elif isinstance(test.ops[0], ast.Eq):
                if isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == 0:
                    if isinstance(test.left, ast.Name):
                        self.guards.nonzero_vars.add(test.left.id)
        # if not x: raise -> x is truthy after
        elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            if isinstance(test.operand, ast.Name):
                self.guards.nonnull_vars.add(test.operand.id)
                self.guards.nonempty_vars.add(test.operand.id)
                self.guards.nonzero_vars.add(test.operand.id)
    
    def visit_If(self, node):
        """Track guards from if conditions, including early-return patterns."""
        old_guards = self.guards.copy()
        
        # ITERATION 611: Handle early-return pattern: if condition: <terminate>
        if self._body_terminates(node.body) and not node.orelse:
            self._extract_inverted_guards(node.test)
            for stmt in node.body:
                self.visit(stmt)
            return  # Inverted guards persist after the if
        
        # Check for None guards: if x is not None:
        if isinstance(node.test, ast.Compare):
            self._extract_none_guard(node.test)
            self._extract_zero_guard(node.test)
            self._extract_empty_guard(node.test)
        
        # Check for truthiness: if x:  (implies x is not None and not empty/zero)
        elif isinstance(node.test, ast.Name):
            self.guards.nonnull_vars.add(node.test.id)
            self.guards.nonempty_vars.add(node.test.id)
            self.guards.nonzero_vars.add(node.test.id)
        
        # Visit the body with updated guards
        for stmt in node.body:
            self.visit(stmt)
        
        # Restore guards for else branch (which has opposite knowledge)
        self.guards = old_guards
        for stmt in node.orelse:
            self.visit(stmt)
    
    def _extract_none_guard(self, node: ast.Compare):
        """Extract 'x is not None' guards."""
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.IsNot):
            if isinstance(node.comparators[0], ast.Constant) and node.comparators[0].value is None:
                if isinstance(node.left, ast.Name):
                    self.guards.nonnull_vars.add(node.left.id)
    
    def _extract_zero_guard(self, node: ast.Compare):
        """Extract 'x != 0' guards."""
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.NotEq):
            if isinstance(node.comparators[0], ast.Constant) and node.comparators[0].value == 0:
                if isinstance(node.left, ast.Name):
                    self.guards.nonzero_vars.add(node.left.id)
        # Also: x > 0
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.Gt):
            if isinstance(node.comparators[0], ast.Constant) and node.comparators[0].value == 0:
                if isinstance(node.left, ast.Name):
                    self.guards.nonzero_vars.add(node.left.id)
    
    def _extract_empty_guard(self, node: ast.Compare):
        """Extract 'len(x) > 0' guards."""
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.Gt):
            if isinstance(node.comparators[0], ast.Constant) and node.comparators[0].value == 0:
                if isinstance(node.left, ast.Call):
                    if isinstance(node.left.func, ast.Name) and node.left.func.id == 'len':
                        if node.left.args and isinstance(node.left.args[0], ast.Name):
                            self.guards.nonempty_vars.add(node.left.args[0].id)
    
    def visit_For(self, node):
        """Track loop iteration patterns for safe indexing."""
        old_guards = self.guards.copy()
        old_loop_vars = self.loop_vars.copy()
        
        # for x in container: (x is guaranteed valid during iteration)
        if isinstance(node.iter, ast.Name):
            container = node.iter.id
            if isinstance(node.target, ast.Name):
                self.loop_vars[node.target.id] = container
        
        # for i, x in enumerate(container): (i is always valid index)
        elif isinstance(node.iter, ast.Call):
            if isinstance(node.iter.func, ast.Name):
                if node.iter.func.id == 'enumerate':
                    self.in_loop_with_enumerate = True
                    if node.iter.args and isinstance(node.iter.args[0], ast.Name):
                        container = node.iter.args[0].id
                        # Track both the index and value
                        if isinstance(node.target, ast.Tuple) and len(node.target.elts) == 2:
                            if isinstance(node.target.elts[0], ast.Name):
                                self.loop_vars[node.target.elts[0].id] = container
                
                # for i in range(len(x)): (i is valid index into x)
                elif node.iter.func.id == 'range':
                    if node.iter.args:
                        arg = node.iter.args[0]
                        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                            if arg.func.id == 'len' and arg.args:
                                if isinstance(arg.args[0], ast.Name):
                                    container = arg.args[0].id
                                    if isinstance(node.target, ast.Name):
                                        self.loop_vars[node.target.id] = container
        
        self.generic_visit(node)
        
        self.guards = old_guards
        self.loop_vars = old_loop_vars
        self.in_loop_with_enumerate = False
    
    def visit_BinOp(self, node):
        """Check for DIV_ZERO with type-awareness."""
        self.generic_visit(node)
        
        if not isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            return
        
        # Get the left operand to check type
        left_str = self._get_name_chain(node.left)
        right_str = self._get_name_chain(node.right)
        
        # FILTER 1: Path division (not numeric)
        if self._is_path_like(left_str):
            return  # Not a bug - it's Path.__truediv__
        
        # FILTER 2: Constant non-zero divisor
        if isinstance(node.right, ast.Constant):
            if isinstance(node.right.value, (int, float)) and node.right.value != 0:
                return  # Safe - constant non-zero
        
        # FILTER 3: Divisor is known non-zero from guards
        if isinstance(node.right, ast.Name):
            if node.right.id in self.guards.nonzero_vars:
                return  # Safe - guarded
        
        # FILTER 4: Division by len(x) - len() always returns >= 0, and
        # division by len(x) where x is non-empty is safe
        if isinstance(node.right, ast.Call):
            if isinstance(node.right.func, ast.Name) and node.right.func.id == 'len':
                if node.right.args and isinstance(node.right.args[0], ast.Name):
                    if node.right.args[0].id in self.guards.nonempty_vars:
                        return  # Safe - len of non-empty container
        
        # FILTER 5: Division by attribute of self (e.g., self.count, self.size)
        # These are typically set in __init__ and validated
        if isinstance(node.right, ast.Attribute):
            if isinstance(node.right.value, ast.Name) and node.right.value.id == 'self':
                attr = node.right.attr.lower()
                # Common safe divisor attributes
                if any(s in attr for s in ['count', 'size', 'num', 'length', 'total', 'n_', 'nfold', 'batch']):
                    return  # Likely safe - instance attribute that's typically validated
        
        # FILTER 6: Division by function parameter with suggestive name
        if isinstance(node.right, ast.Name):
            param_name = node.right.id.lower()
            # Parameters named 'n', 'count', 'size', 'num_*' etc are typically validated by caller
            if any(s in param_name for s in ['count', 'size', 'num_', 'n_', 'nfold', 'batch_size', 'world_size']):
                return  # Likely safe - named parameter suggests validation
        
        # FILTER 7: math.ceil(x / y) or similar - often used for partitioning
        # where y is from config/validated source
        parent = getattr(node, '_parent', None)
        if isinstance(parent, ast.Call):
            if isinstance(parent.func, ast.Attribute):
                if parent.func.attr in ('ceil', 'floor'):
                    if isinstance(node.right, ast.Attribute):
                        return  # Likely safe - ceiling/floor of config value
        
        # FILTER 8: Division inside numpy/pandas operations (they handle edge cases)
        if 'np.' in left_str or 'pd.' in left_str or left_str.startswith(('np', 'pd', 'torch')):
            return  # NumPy/Pandas often handle zeros gracefully
        
        # This is a potential real DIV_ZERO bug
        self.bugs['div_zero'].append({
            'line': node.lineno,
            'col': node.col_offset,
            'divisor': right_str,
            'reason': 'Variable divisor without non-zero guard'
        })
    
    def visit_Attribute(self, node):
        """Check for NULL_PTR with semantic awareness."""
        self.generic_visit(node)
        
        if not isinstance(node.value, ast.Name):
            return
        
        name = node.value.id
        
        # FILTER 1: Known never-None names
        if name in self.NEVER_NONE:
            return
        
        # FILTER 2: Variable is guarded as non-None
        if name in self.guards.nonnull_vars:
            return
        
        # FILTER 3: Only flag names with suspicious patterns
        # Variables named result, response, match, etc. are common None sources
        suspicious_patterns = ['result', 'response', 'found', 'match', 'fetched']
        name_lower = name.lower()
        if not any(p in name_lower for p in suspicious_patterns):
            return  # Not a suspicious name, likely safe
        
        # FILTER 4: If accessing common safe attributes, skip
        # These methods/attrs typically don't fail even on unusual objects
        safe_attrs = {'__class__', '__name__', '__dict__', '__doc__', '__module__',
                      'keys', 'values', 'items', 'get', 'copy', 'update'}
        if node.attr in safe_attrs:
            return
        
        # FILTER 5: Check for assignment patterns that indicate non-None
        # e.g., result = some_call() is less likely None than result = dict.get(...)
        # This is a heuristic - we can't know for sure without deeper analysis
        
        # This is a potential NULL_PTR bug
        self.bugs['null_ptr'].append({
            'line': node.lineno,
            'col': node.col_offset,
            'var': name,
            'attr': node.attr,
            'reason': f'{name} could be None (no guard found)'
        })
    
    def visit_Subscript(self, node):
        """Check for BOUNDS with loop-awareness."""
        self.generic_visit(node)
        
        # FILTER 1: Index is from enumerate or range(len())
        if isinstance(node.slice, ast.Name):
            idx_name = node.slice.id
            if idx_name in self.loop_vars:
                # Check if indexing the same container we're iterating
                container_name = self._get_name_chain(node.value)
                if self.loop_vars[idx_name] == container_name:
                    return  # Safe - iteration-based indexing
        
        # FILTER 2: Constant index on non-empty container
        if isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, int):
                container_name = self._get_name_chain(node.value)
                if container_name in self.guards.nonempty_vars:
                    if node.slice.value in (0, -1):
                        return  # Safe - first/last element of non-empty
        
        # FILTER 3: len(x)-1 pattern (safe if x is non-empty)
        if isinstance(node.slice, ast.BinOp) and isinstance(node.slice.op, ast.Sub):
            if isinstance(node.slice.left, ast.Call):
                call = node.slice.left
                if isinstance(call.func, ast.Name) and call.func.id == 'len':
                    if isinstance(node.slice.right, ast.Constant) and node.slice.right.value >= 1:
                        # len(x) - n where n >= 1 is safe for non-empty x
                        if call.args and isinstance(call.args[0], ast.Name):
                            if call.args[0].id in self.guards.nonempty_vars:
                                return
        
        # Check for dangerous patterns
        if isinstance(node.slice, ast.BinOp):
            slice_str = ast.unparse(node.slice) if hasattr(ast, 'unparse') else ''
            
            # DANGEROUS: x[len(x)] is always OOB!
            if isinstance(node.slice, ast.Call):
                if isinstance(node.slice.func, ast.Name) and node.slice.func.id == 'len':
                    self.bugs['bounds'].append({
                        'line': node.lineno,
                        'col': node.col_offset,
                        'reason': 'x[len(x)] is always out of bounds'
                    })
                    return
            
            # DANGEROUS: computed index without range check
            # Only flag if it looks suspicious
            if 'len(' in slice_str and '+' in slice_str:
                self.bugs['bounds'].append({
                    'line': node.lineno,
                    'col': node.col_offset,
                    'slice': slice_str,
                    'reason': 'Computed index with addition may be OOB'
                })
    
    def _get_name_chain(self, node) -> str:
        """Get the name of a variable or attribute chain."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_name_chain(node.value)
            return f'{base}.{node.attr}'
        elif isinstance(node, ast.Subscript):
            return self._get_name_chain(node.value)
        elif isinstance(node, ast.Call):
            return self._get_name_chain(node.func)
        return ''
    
    def _is_path_like(self, name: str) -> bool:
        """Check if a name is path-like (uses / for path concatenation)."""
        name_lower = name.lower()
        return any(p in name_lower for p in self.PATH_NAMES)


def analyze_with_guards(filepath: Path) -> dict:
    """Analyze a file with guard-based FP reduction."""
    analyzer = ImprovedBugAnalyzer(filepath)
    return analyzer.analyze()


def main():
    base_path = Path(__file__).parent / 'external_tools'
    
    repos = {
        'Qlib': ['qlib/backtest', 'qlib/utils'],
        'DeepSpeed': ['deepspeed/runtime'],
        'FLAML': ['flaml/automl'],
        'GraphRAG': ['graphrag/index'],
        'PromptFlow': ['src/promptflow-core/promptflow'],
    }
    
    print('=' * 80)
    print('IMPROVED ANALYSIS WITH GUARD-BASED FP REDUCTION')
    print('=' * 80)
    
    total_bugs = defaultdict(int)
    sample_bugs = defaultdict(list)
    files_analyzed = 0
    
    for repo, dirs in repos.items():
        repo_path = base_path / repo
        if not repo_path.exists():
            continue
        
        for subdir in dirs:
            dir_path = repo_path / subdir
            if not dir_path.exists():
                continue
            
            for pyfile in list(dir_path.rglob('*.py'))[:30]:
                if 'test' in str(pyfile).lower():
                    continue
                
                bugs = analyze_with_guards(pyfile)
                files_analyzed += 1
                
                for bug_type, bug_list in bugs.items():
                    total_bugs[bug_type] += len(bug_list)
                    for bug in bug_list[:2]:
                        bug['file'] = str(pyfile.relative_to(base_path))
                        bug['repo'] = repo
                        if len(sample_bugs[bug_type]) < 10:
                            sample_bugs[bug_type].append(bug)
    
    print(f'\nFiles analyzed: {files_analyzed}')
    print('\nBug counts (after FP reduction):')
    for bug_type in ['div_zero', 'null_ptr', 'bounds', 'type_confusion']:
        print(f'  {bug_type.upper()}: {total_bugs[bug_type]}')
    
    print('\n' + '=' * 80)
    print('SAMPLE BUGS (these should be real issues)')
    print('=' * 80)
    
    for bug_type in ['div_zero', 'null_ptr', 'bounds']:
        print(f'\n{bug_type.upper()}:')
        for bug in sample_bugs[bug_type][:5]:
            print(f'  [{bug["repo"]}] {bug["file"]}:{bug["line"]}')
            if 'reason' in bug:
                print(f'    Reason: {bug["reason"]}')


if __name__ == '__main__':
    main()
