"""
Call Graph Construction for Interprocedural Analysis.

Implements static call graph construction as defined in python-barrier-certificate-theory.md §9.5.2:

Definition (Static Call Graph): G_call = (V, E) where:
- V is the set of all functions (code objects) in the program
- E ⊆ V × V where (f, g) ∈ E iff f contains a call site that may invoke g

For Python, this is approximate due to:
1. First-class functions
2. Dynamic dispatch
3. Reflection
4. Imports
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
import ast
import types
import dis


@dataclass
class CallSite:
    """
    A call site π_c in a function.
    
    Contains:
    - The callee expression (the function being called)
    - Arguments (positional and keyword)
    - A return continuation (where control resumes after the call)
    """
    # Location
    file_path: str
    line_number: int
    col_offset: int
    
    # Caller info
    caller_name: str  # Fully qualified name
    bytecode_offset: Optional[int] = None
    
    # Callee info (what we can statically determine)
    callee_name: Optional[str] = None  # May be unknown for dynamic calls
    callee_attribute: Optional[str] = None  # For method calls: obj.method
    is_method_call: bool = False
    
    # Arguments (for context-sensitive analysis)
    num_args: int = 0
    has_starargs: bool = False
    has_kwargs: bool = False


@dataclass
class FunctionInfo:
    """Information about a function definition."""
    name: str  # Simple name
    qualified_name: str  # module.class.function format
    file_path: str
    line_number: int
    
    # Parameters for summary computation
    parameters: List[str] = field(default_factory=list)
    has_varargs: bool = False
    has_kwargs: bool = False
    vararg_name: Optional[str] = None  # Name of *args parameter
    kwarg_name: Optional[str] = None   # Name of **kwargs parameter
    
    # ITERATION 610: Parameter nullability from type annotations
    # Maps param_index -> True if Optional/nullable, False if non-nullable typed
    # None means no type annotation
    param_nullable: Dict[int, Optional[bool]] = field(default_factory=dict)
    
    # Call sites within this function
    call_sites: List[CallSite] = field(default_factory=list)
    
    # Return statements (for dataflow)
    return_count: int = 0
    
    # Code object reference (if available)
    code_object: Optional[types.CodeType] = None


@dataclass
class CallGraph:
    """
    Static call graph G_call = (V, E).
    
    Provides sound over-approximation: every actual call is represented.
    """
    # V: set of all functions
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    
    # E: edges (caller_qname -> set of callee_qnames)
    edges: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Reverse edges for bottom-up traversal
    reverse_edges: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Call sites indexed by caller
    call_sites_by_caller: Dict[str, List[CallSite]] = field(default_factory=dict)
    
    # External/library calls (callee not in V)
    external_calls: Dict[str, Set[str]] = field(default_factory=dict)
    
    def add_function(self, func: FunctionInfo) -> None:
        """Add a function to the graph."""
        self.functions[func.qualified_name] = func
        if func.qualified_name not in self.edges:
            self.edges[func.qualified_name] = set()
        if func.qualified_name not in self.reverse_edges:
            self.reverse_edges[func.qualified_name] = set()
    
    def add_edge(self, caller: str, callee: str) -> None:
        """Add a call edge."""
        if caller not in self.edges:
            self.edges[caller] = set()
        self.edges[caller].add(callee)
        
        if callee not in self.reverse_edges:
            self.reverse_edges[callee] = set()
        self.reverse_edges[callee].add(caller)
    
    def add_external_call(self, caller: str, callee: str) -> None:
        """Record a call to external/library function."""
        if caller not in self.external_calls:
            self.external_calls[caller] = set()
        self.external_calls[caller].add(callee)
    
    def get_function(self, name: str) -> Optional[FunctionInfo]:
        """Get function info by qualified name."""
        return self.functions.get(name)
    
    def get_callees(self, func: str) -> Set[str]:
        """Get all functions called by func."""
        return self.edges.get(func, set())
    
    def get_callers(self, func: str) -> Set[str]:
        """Get all functions that call func."""
        return self.reverse_edges.get(func, set())
    
    def compute_sccs(self) -> List[Set[str]]:
        """
        Compute strongly connected components using Tarjan's algorithm.
        
        Returns SCCs in reverse topological order (leaves first).
        """
        index_counter = [0]
        stack = []
        lowlink = {}
        index = {}
        on_stack = {}
        sccs = []
        
        def strongconnect(v):
            index[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True
            
            for w in self.edges.get(v, set()):
                if w not in self.functions:
                    continue  # External call
                if w not in index:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif on_stack.get(w, False):
                    lowlink[v] = min(lowlink[v], index[w])
            
            if lowlink[v] == index[v]:
                scc = set()
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.add(w)
                    if w == v:
                        break
                sccs.append(scc)
        
        for v in self.functions:
            if v not in index:
                strongconnect(v)
        
        return sccs  # Already in reverse topological order
    
    def is_recursive(self, func: str) -> bool:
        """Check if a function is (mutually) recursive."""
        for scc in self.compute_sccs():
            if func in scc and len(scc) > 1:
                return True
            if func in scc and func in self.edges.get(func, set()):
                return True  # Self-recursive
        return False
    
    def get_reachable_from(self, entry_points: Set[str]) -> Set[str]:
        """Get all functions reachable from entry points."""
        reachable = set()
        worklist = list(entry_points)
        
        while worklist:
            func = worklist.pop()
            if func in reachable:
                continue
            if func not in self.functions:
                continue
            reachable.add(func)
            worklist.extend(self.edges.get(func, set()))
        
        return reachable
    
    def resolve_cross_module_calls(self) -> int:
        """
        Resolve external calls that should be internal edges.
        
        After building the call graph from multiple files, some calls
        tracked as "external" are actually to functions in the graph.
        This method resolves those and converts them to internal edges.
        
        Returns:
            Number of external calls resolved to internal edges.
        """
        resolved_count = 0
        
        # Build a lookup map: function simple name -> set of qualified names
        name_to_qnames: Dict[str, Set[str]] = {}
        for qname in self.functions:
            # Extract simple name (last component)
            simple_name = qname.split('.')[-1]
            if simple_name not in name_to_qnames:
                name_to_qnames[simple_name] = set()
            name_to_qnames[simple_name].add(qname)
        
        # Also build exact qualified name lookup
        qname_to_func = {qname: qname for qname in self.functions}
        
        # For each caller, check external calls
        for caller, external_callees in list(self.external_calls.items()):
            resolved_callees = set()
            
            for external_name in external_callees:
                resolved_qname = None
                
                # Try exact match first
                if external_name in qname_to_func:
                    resolved_qname = external_name
                else:
                    # Try to match by simple name
                    simple_name = external_name.split('.')[-1]
                    if simple_name in name_to_qnames:
                        candidates = name_to_qnames[simple_name]
                        
                        # If external_name is qualified (has dots), try prefix matching
                        if '.' in external_name:
                            # e.g., external_name = "module_a.source_func"
                            # Try to find qname that ends with this
                            for qname in candidates:
                                if qname.endswith(external_name) or external_name == qname:
                                    resolved_qname = qname
                                    break
                            
                            # If no suffix match, check if any candidate's module matches
                            if not resolved_qname:
                                for qname in candidates:
                                    # e.g., qname = "module_a.source_func", external_name = "module_a.source_func"
                                    if qname == external_name:
                                        resolved_qname = qname
                                        break
                        else:
                            # Simple name only - could be ambiguous, but take first match
                            # (In a real system, we'd use import tracking to resolve)
                            if len(candidates) == 1:
                                resolved_qname = list(candidates)[0]
                
                if resolved_qname and resolved_qname in self.functions:
                    # Convert to internal edge
                    self.add_edge(caller, resolved_qname)
                    resolved_callees.add(external_name)
                    resolved_count += 1
            
            # Remove resolved callees from external_calls
            for resolved in resolved_callees:
                self.external_calls[caller].discard(resolved)
            
            # Clean up empty sets
            if not self.external_calls[caller]:
                del self.external_calls[caller]
        
        # ITERATION 610: Resolve self.method calls to qualified class method names
        resolved_count += self._resolve_self_method_calls()
        
        return resolved_count
    
    def _resolve_self_method_calls(self) -> int:
        """
        Resolve self.method calls to their qualified method names.
        
        When a method calls self.other_method(), we need to resolve this to
        the qualified name like module.ClassName.other_method.
        
        Returns:
            Number of self-method calls resolved.
        """
        resolved_count = 0
        
        for caller in list(self.external_calls.keys()):
            # Get the caller's class (if any)
            # Caller format: module.ClassName.method_name
            parts = caller.rsplit('.', 2)
            if len(parts) < 2:
                continue
            
            # Check if this is a method (has a class component)
            # Try to find the class by looking for other methods with same prefix
            caller_prefix = '.'.join(parts[:-1])  # e.g., "module.ClassName"
            
            resolved_callees = set()
            for external_name in self.external_calls[caller]:
                # Check for self.method pattern
                if external_name.startswith('self.'):
                    method_name = external_name[5:]  # Remove "self."
                    # Try to resolve to caller's class
                    resolved_qname = f"{caller_prefix}.{method_name}"
                    
                    if resolved_qname in self.functions:
                        self.add_edge(caller, resolved_qname)
                        resolved_callees.add(external_name)
                        resolved_count += 1
            
            # Remove resolved callees
            for resolved in resolved_callees:
                self.external_calls[caller].discard(resolved)
            
            if not self.external_calls[caller]:
                del self.external_calls[caller]
        
        return resolved_count


class CallGraphBuilder(ast.NodeVisitor):
    """
    AST visitor that builds a call graph from Python source.
    
    Handles:
    - Function/method definitions
    - Call expressions
    - Import tracking for cross-file resolution
    """
    
    def __init__(self, file_path: str, module_name: str):
        self.file_path = file_path
        self.module_name = module_name
        self.graph = CallGraph()
        
        # Current context
        self.current_class: Optional[str] = None
        self.current_function: Optional[str] = None
        self.function_stack: List[str] = []
        
        # Name bindings for callee resolution
        self.imports: Dict[str, str] = {}  # local name -> qualified name
        self.local_defs: Dict[str, str] = {}  # local name -> qualified name
    
    def qualified_name(self, name: str) -> str:
        """Build fully qualified name from current context."""
        parts = [self.module_name]
        if self.current_class:
            parts.append(self.current_class)
        parts.append(name)
        return '.'.join(parts)
    
    def current_qualified_name(self) -> str:
        """Get the fully qualified name of the current function."""
        if self.function_stack:
            return self.function_stack[-1]
        return self.module_name
    
    def visit_Import(self, node: ast.Import) -> None:
        """Handle 'import x' statements."""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Handle 'from x import y' statements."""
        module = node.module or ''
        for alias in node.names:
            name = alias.asname or alias.name
            if alias.name == '*':
                # Star import - can't track precisely
                pass
            else:
                qualified = f"{module}.{alias.name}" if module else alias.name
                self.imports[name] = qualified
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Handle class definitions."""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class
    
    def _extract_param_nullability(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Dict[int, Optional[bool]]:
        """
        Extract parameter nullability from type annotations.
        
        ITERATION 610: Reduce false positive NULL_PTR for typed parameters.
        Returns dict mapping param_index -> nullable (True if Optional, False if typed non-nullable, None if no annotation).
        """
        result: Dict[int, Optional[bool]] = {}
        idx = 0
        
        # Process all argument types in order
        all_args = list(node.args.args) + list(node.args.posonlyargs) + list(node.args.kwonlyargs)
        
        for arg in all_args:
            if arg.annotation:
                result[idx] = self._annotation_is_optional(arg.annotation)
            else:
                result[idx] = None  # No annotation
            idx += 1
        
        return result
    
    def _annotation_is_optional(self, annotation: ast.AST) -> bool:
        """
        Check if a type annotation indicates Optional/nullable.
        
        Handles:
        - Optional[X] -> True
        - Union[X, None] -> True
        - X | None -> True (Python 3.10+)
        - None -> True
        - Everything else -> False (typed non-nullable)
        """
        # None literal
        if isinstance(annotation, ast.Constant) and annotation.value is None:
            return True
        
        # ast.Name("None")
        if isinstance(annotation, ast.Name) and annotation.id == 'None':
            return True
        
        # Subscript: Optional[X] or Union[X, None]
        if isinstance(annotation, ast.Subscript):
            if isinstance(annotation.value, ast.Attribute):
                attr_name = annotation.value.attr
            elif isinstance(annotation.value, ast.Name):
                attr_name = annotation.value.id
            else:
                return False
            
            if attr_name == 'Optional':
                return True
            if attr_name == 'Union':
                # Check if None is in the union
                if isinstance(annotation.slice, ast.Tuple):
                    for elt in annotation.slice.elts:
                        if self._annotation_is_optional(elt):
                            return True
                elif self._annotation_is_optional(annotation.slice):
                    return True
        
        # BinOp: X | None (Python 3.10+)
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            if self._annotation_is_optional(annotation.left) or self._annotation_is_optional(annotation.right):
                return True
        
        return False
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Handle function definitions."""
        self._visit_function(node)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Handle async function definitions."""
        self._visit_function(node)
    
    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Common handler for function definitions."""
        qname = self.qualified_name(node.name)
        
        # Extract parameters
        params = []
        for arg in node.args.args:
            params.append(arg.arg)
        for arg in node.args.posonlyargs:
            params.append(arg.arg)
        for arg in node.args.kwonlyargs:
            params.append(arg.arg)
        
        # ITERATION 610: Extract parameter nullability from type annotations
        param_nullable = self._extract_param_nullability(node)
        
        # Extract vararg and kwarg names
        vararg_name = node.args.vararg.arg if node.args.vararg else None
        kwarg_name = node.args.kwarg.arg if node.args.kwarg else None
        
        # Compile the function to get code object
        code_obj = None
        try:
            # Wrap function in a module and compile
            module = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(module)
            compiled = compile(module, filename=self.file_path, mode='exec')
            # Extract the function code object
            for const in compiled.co_consts:
                if isinstance(const, types.CodeType) and const.co_name == node.name:
                    code_obj = const
                    break
        except Exception:
            # Compilation failed - code object remains None
            pass
        
        func_info = FunctionInfo(
            name=node.name,
            qualified_name=qname,
            file_path=self.file_path,
            line_number=node.lineno,
            parameters=params,
            has_varargs=node.args.vararg is not None,
            has_kwargs=node.args.kwarg is not None,
            vararg_name=vararg_name,
            kwarg_name=kwarg_name,
            param_nullable=param_nullable,
            code_object=code_obj,
        )
        
        self.graph.add_function(func_info)
        self.local_defs[node.name] = qname
        
        # Visit body with this function as context
        old_function = self.current_function
        self.current_function = node.name
        self.function_stack.append(qname)
        
        # Count returns
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Return):
                func_info.return_count += 1
        
        self.generic_visit(node)
        
        self.function_stack.pop()
        self.current_function = old_function
    
    def visit_Call(self, node: ast.Call) -> None:
        """Handle call expressions."""
        if not self.function_stack:
            # Top-level call (module initialization)
            caller = self.module_name
        else:
            caller = self.current_qualified_name()
        
        call_site = CallSite(
            file_path=self.file_path,
            line_number=node.lineno,
            col_offset=node.col_offset,
            caller_name=caller,
            num_args=len(node.args),
            has_starargs=any(isinstance(a, ast.Starred) for a in node.args),
            has_kwargs=len(node.keywords) > 0,
        )
        
        # Resolve callee
        callee_name = self._resolve_callee(node.func)
        call_site.callee_name = callee_name
        
        if isinstance(node.func, ast.Attribute):
            call_site.is_method_call = True
            call_site.callee_attribute = node.func.attr
        
        # Store call site
        if caller not in self.graph.call_sites_by_caller:
            self.graph.call_sites_by_caller[caller] = []
        self.graph.call_sites_by_caller[caller].append(call_site)
        
        # Add edge if we can resolve callee
        if callee_name:
            if callee_name in self.local_defs:
                self.graph.add_edge(caller, self.local_defs[callee_name])
            elif callee_name in self.imports:
                # External or cross-module call
                self.graph.add_external_call(caller, self.imports[callee_name])
            elif '.' not in callee_name and callee_name in self.graph.functions:
                self.graph.add_edge(caller, callee_name)
            else:
                # Unresolved - could be builtin or dynamic
                self.graph.add_external_call(caller, callee_name)
        
        self.generic_visit(node)
    
    def _resolve_callee(self, node: ast.expr) -> Optional[str]:
        """Try to resolve the callee name from an expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # obj.method - try to resolve obj
            base = self._resolve_callee(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        elif isinstance(node, ast.Call):
            # f()(args) - can't statically resolve
            return None
        elif isinstance(node, ast.Subscript):
            # f[x](args) - can't statically resolve
            return None
        return None


def build_call_graph_from_file(file_path: Path, module_name: str = None) -> CallGraph:
    """Build call graph from a single Python file."""
    if module_name is None:
        module_name = file_path.stem
    
    with open(file_path, 'r', encoding='utf-8') as f:
        source = f.read()
    
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return CallGraph()  # Return empty graph on parse error
    
    builder = CallGraphBuilder(str(file_path), module_name)
    builder.visit(tree)
    
    # Populate FunctionInfo.call_sites from call_sites_by_caller
    for caller_qname, call_sites in builder.graph.call_sites_by_caller.items():
        func_info = builder.graph.functions.get(caller_qname)
        if func_info:
            func_info.call_sites.extend(call_sites)
    
    return builder.graph


def build_call_graph_from_directory(
    root_path: Path,
    exclude_patterns: List[str] = None
) -> CallGraph:
    """Build call graph from all Python files in a directory."""
    exclude_patterns = exclude_patterns or ['__pycache__', '.git', 'venv', '.venv', 'node_modules']
    
    import fnmatch
    
    combined = CallGraph()
    
    for py_file in root_path.rglob('*.py'):
        # Check exclusions using both substring and glob matching
        rel_str = str(py_file.relative_to(root_path))
        abs_str = str(py_file)
        excluded = False
        for p in exclude_patterns:
            # Glob-style patterns (contain *, ?, [)
            if any(c in p for c in ('*', '?', '[')):
                if fnmatch.fnmatch(rel_str, p):
                    excluded = True
                    break
            else:
                # Simple substring match (for __pycache__, .git, etc.)
                if p in abs_str:
                    excluded = True
                    break
        if excluded:
            continue
        
        # Compute module name from path
        try:
            rel_path = py_file.relative_to(root_path)
            parts = list(rel_path.parts[:-1]) + [py_file.stem]
            if parts[-1] == '__init__':
                parts = parts[:-1]
            module_name = '.'.join(parts) if parts else py_file.stem
        except ValueError:
            module_name = py_file.stem
        
        file_graph = build_call_graph_from_file(py_file, module_name)
        
        # Merge into combined
        for qname, func in file_graph.functions.items():
            combined.add_function(func)
        
        for caller, callees in file_graph.edges.items():
            for callee in callees:
                combined.add_edge(caller, callee)
        
        for caller, callees in file_graph.external_calls.items():
            for callee in callees:
                combined.add_external_call(caller, callee)
        
        for caller, sites in file_graph.call_sites_by_caller.items():
            if caller not in combined.call_sites_by_caller:
                combined.call_sites_by_caller[caller] = []
            combined.call_sites_by_caller[caller].extend(sites)
    
    # Populate FunctionInfo.call_sites from call_sites_by_caller
    for caller_qname, call_sites in combined.call_sites_by_caller.items():
        func_info = combined.functions.get(caller_qname)
        if func_info:
            func_info.call_sites.extend(call_sites)
    
    # ITERATION 531: Resolve cross-module calls
    # After collecting all functions from all modules, resolve external calls
    # that are actually to functions within the project
    resolved = combined.resolve_cross_module_calls()
    if resolved > 0:
        # Update call sites with resolved callees
        for caller_qname, call_sites in combined.call_sites_by_caller.items():
            for site in call_sites:
                if site.callee_name and site.callee_name in combined.functions:
                    # Already resolved
                    continue
                # Check if this was an external call that got resolved
                if caller_qname in combined.edges:
                    for resolved_callee in combined.edges[caller_qname]:
                        # Match by simple name
                        if site.callee_name and resolved_callee.endswith(site.callee_name):
                            site.callee_name = resolved_callee
                            break
    
    return combined


def print_call_graph(graph: CallGraph, max_funcs: int = 50) -> None:
    """Print a human-readable representation of the call graph."""
    print(f"Call Graph: {len(graph.functions)} functions, {sum(len(e) for e in graph.edges.values())} edges")
    print()
    
    funcs = list(graph.functions.keys())[:max_funcs]
    for qname in funcs:
        func = graph.functions[qname]
        callees = graph.get_callees(qname)
        external = graph.external_calls.get(qname, set())
        
        print(f"  {qname}")
        print(f"    File: {func.file_path}:{func.line_number}")
        print(f"    Params: {func.parameters}")
        if callees:
            print(f"    Calls: {callees}")
        if external:
            print(f"    External: {external}")
        print()


__all__ = [
    'CallSite',
    'FunctionInfo',
    'CallGraph',
    'CallGraphBuilder',
    'build_call_graph_from_file',
    'build_call_graph_from_directory',
    'print_call_graph',
]
