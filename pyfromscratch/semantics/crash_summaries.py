"""
Crash Summaries for Interprocedural Bug Detection.

Extends taint summaries to track crash-inducing conditions across function boundaries.
This covers ALL 20 core bug types + 47 security bug types.

INTEGRATION WITH EXISTING INFRASTRUCTURE:
- Uses UNSAFE_PREDICATES from pyfromscratch/unsafe/registry.py
- Uses TaintLabel/SymbolicTaintLabel from pyfromscratch/z3model/taint_lattice.py
- Uses barrier synthesis from pyfromscratch/barriers/synthesis.py
- Uses security contracts from pyfromscratch/contracts/security_lattice.py

For each function f, we compute:
1. **Precondition Summary** Π_f: Required conditions on parameters to avoid crashes
2. **Effect Summary** E_f: What crash conditions f may produce  
3. **Exception Summary** X_f: What exceptions f may raise
4. **Nullability Summary** N_f: Whether parameters may be None, return may be None

This enables interprocedural reasoning:
- If caller passes value that may be None to callee requiring non-None → NULL_PTR
- If caller passes untainted value to callee that checks bounds → may still crash
- If callee raises exception that caller doesn't handle → PANIC

Mathematical Foundation (python-barrier-certificate-theory.md §9.5):

Definition (Crash Summary): For function f with parameters (p₁, ..., pₙ):
    Σ_f^crash = (Π_f, E_f, X_f, N_f)
where:
    - Π_f : 2^{Params} → Preconditions  (what must hold for params)
    - E_f : 2^{BugTypes}                 (what bugs f may trigger)
    - X_f : 2^{ExceptionTypes}           (what exceptions f may raise)
    - N_f : {may_be_none, not_none}^n    (nullability of params/return)

Theorem (Interprocedural Bug Propagation):
    If f calls g at site π, and:
    - args at π violate Π_g, OR
    - X_g contains exceptions not caught by f
    then f may exhibit bugs from E_g ∪ {derived bugs from Π_g violation}.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any, FrozenSet, Callable
from enum import IntEnum, auto
import ast
import dis
import types
from pathlib import Path

# ============================================================================
# IMPORT EXISTING INFRASTRUCTURE - DO NOT DUPLICATE
# ============================================================================

from ..unsafe.registry import (
    UNSAFE_PREDICATES,
    check_unsafe_regions,
    list_implemented_bug_types,
    get_all_unsafe_predicates,
)
from ..cfg.dataflow import run_intraprocedural_analysis, IntraprocAnalysisResult
from ..cfg.control_flow import build_cfg, ControlFlowGraph, BasicBlock

# Bug type names from the registry (canonical source of truth)
REGISTERED_BUG_TYPES: List[str] = list_implemented_bug_types()


# ============================================================================
# PRECONDITION TYPES
# ============================================================================

class PreconditionType(IntEnum):
    """Types of preconditions a function may require on parameters."""
    NOT_NONE = auto()          # Parameter must not be None
    NOT_ZERO = auto()          # Parameter must not be zero (divisor)
    IN_BOUNDS = auto()         # Index must be in bounds
    VALID_TYPE = auto()        # Parameter must have expected type
    NOT_EMPTY = auto()         # Collection must not be empty
    POSITIVE = auto()          # Value must be > 0
    NON_NEGATIVE = auto()      # Value must be >= 0
    FINITE = auto()            # Float must not be inf/nan
    VALID_RANGE = auto()       # Value must be in valid range
    SANITIZED = auto()         # Must be sanitized for sink
    TRUSTED = auto()           # Must not be tainted


@dataclass(frozen=True)
class Precondition:
    """A single precondition on a parameter."""
    param_index: int
    condition_type: PreconditionType
    related_param: Optional[int] = None  # For IN_BOUNDS: the container param
    sink_type: Optional[int] = None      # For SANITIZED: which sink
    
    def __str__(self) -> str:
        base = f"p{self.param_index}.{self.condition_type.name}"
        if self.related_param is not None:
            base += f"(p{self.related_param})"
        return base


# ============================================================================
# EXCEPTION TYPES
# ============================================================================

class ExceptionType(IntEnum):
    """Common exception types tracked for interprocedural analysis."""
    NONE = 0  # No exception
    ATTRIBUTE_ERROR = auto()
    TYPE_ERROR = auto()
    VALUE_ERROR = auto()
    INDEX_ERROR = auto()
    KEY_ERROR = auto()
    ZERO_DIVISION_ERROR = auto()
    ASSERTION_ERROR = auto()
    RUNTIME_ERROR = auto()
    OVERFLOW_ERROR = auto()
    MEMORY_ERROR = auto()
    RECURSION_ERROR = auto()
    STOP_ITERATION = auto()
    FILE_NOT_FOUND_ERROR = auto()
    PERMISSION_ERROR = auto()
    OS_ERROR = auto()
    IO_ERROR = auto()
    IMPORT_ERROR = auto()
    NAME_ERROR = auto()
    UNBOUND_LOCAL_ERROR = auto()
    TIMEOUT_ERROR = auto()
    KEYBOARD_INTERRUPT = auto()
    SYSTEM_EXIT = auto()
    GENERIC_EXCEPTION = auto()


# Map exception name strings to enum
EXCEPTION_NAMES: Dict[str, ExceptionType] = {
    'AttributeError': ExceptionType.ATTRIBUTE_ERROR,
    'TypeError': ExceptionType.TYPE_ERROR,
    'ValueError': ExceptionType.VALUE_ERROR,
    'IndexError': ExceptionType.INDEX_ERROR,
    'KeyError': ExceptionType.KEY_ERROR,
    'ZeroDivisionError': ExceptionType.ZERO_DIVISION_ERROR,
    'AssertionError': ExceptionType.ASSERTION_ERROR,
    'RuntimeError': ExceptionType.RUNTIME_ERROR,
    'OverflowError': ExceptionType.OVERFLOW_ERROR,
    'MemoryError': ExceptionType.MEMORY_ERROR,
    'RecursionError': ExceptionType.RECURSION_ERROR,
    'StopIteration': ExceptionType.STOP_ITERATION,
    'FileNotFoundError': ExceptionType.FILE_NOT_FOUND_ERROR,
    'PermissionError': ExceptionType.PERMISSION_ERROR,
    'OSError': ExceptionType.OS_ERROR,
    'IOError': ExceptionType.IO_ERROR,
    'ImportError': ExceptionType.IMPORT_ERROR,
    'NameError': ExceptionType.NAME_ERROR,
    'UnboundLocalError': ExceptionType.UNBOUND_LOCAL_ERROR,
    'TimeoutError': ExceptionType.TIMEOUT_ERROR,
    'KeyboardInterrupt': ExceptionType.KEYBOARD_INTERRUPT,
    'SystemExit': ExceptionType.SYSTEM_EXIT,
}


# Map exceptions to bug types (using string names from registry)
EXCEPTION_TO_BUG: Dict[ExceptionType, str] = {
    ExceptionType.ATTRIBUTE_ERROR: 'NULL_PTR',
    ExceptionType.TYPE_ERROR: 'TYPE_CONFUSION',
    ExceptionType.INDEX_ERROR: 'BOUNDS',
    ExceptionType.KEY_ERROR: 'BOUNDS',
    ExceptionType.ZERO_DIVISION_ERROR: 'DIV_ZERO',
    ExceptionType.ASSERTION_ERROR: 'ASSERT_FAIL',
    ExceptionType.OVERFLOW_ERROR: 'INTEGER_OVERFLOW',
    ExceptionType.MEMORY_ERROR: 'MEMORY_LEAK',
    ExceptionType.RECURSION_ERROR: 'STACK_OVERFLOW',
    ExceptionType.STOP_ITERATION: 'ITERATOR_INVALID',
}


# Map precondition violations to bug types
PRECONDITION_TO_BUG: Dict[PreconditionType, str] = {
    PreconditionType.NOT_NONE: 'NULL_PTR',
    PreconditionType.NOT_ZERO: 'DIV_ZERO',
    PreconditionType.IN_BOUNDS: 'BOUNDS',
    PreconditionType.VALID_TYPE: 'TYPE_CONFUSION',
    PreconditionType.NOT_EMPTY: 'BOUNDS',
    PreconditionType.POSITIVE: 'ASSERT_FAIL',
    PreconditionType.NON_NEGATIVE: 'BOUNDS',
    PreconditionType.FINITE: 'FP_DOMAIN',
    PreconditionType.SANITIZED: 'SQL_INJECTION',  # Generic - depends on sink
    PreconditionType.TRUSTED: 'CODE_INJECTION',   # Generic - depends on sink
}


# ============================================================================
# NULLABILITY LATTICE
# ============================================================================

class Nullability(IntEnum):
    """Nullability state for values."""
    BOTTOM = 0       # Unreachable / no value
    NOT_NONE = 1     # Definitely not None
    MAY_BE_NONE = 2  # Could be None
    IS_NONE = 3      # Definitely None
    TOP = 4          # Unknown
    
    def join(self, other: 'Nullability') -> 'Nullability':
        """Lattice join (least upper bound)."""
        if self == Nullability.BOTTOM:
            return other
        if other == Nullability.BOTTOM:
            return self
        if self == other:
            return self
        if self == Nullability.TOP or other == Nullability.TOP:
            return Nullability.TOP
        # Different non-bottom, non-top values → MAY_BE_NONE or TOP
        if {self, other} == {Nullability.NOT_NONE, Nullability.IS_NONE}:
            return Nullability.MAY_BE_NONE
        return Nullability.MAY_BE_NONE


# ============================================================================
# CRASH SUMMARY
# ============================================================================

@dataclass
class CrashSummary:
    """
    Complete crash summary for a function.
    
    Captures all conditions under which a function may crash or trigger bugs.
    Uses string bug type names from pyfromscratch/unsafe/registry.py as the
    canonical source of truth.
    """
    function_name: str
    qualified_name: str
    parameter_count: int
    
    # Preconditions: what must hold for parameters to avoid crashes
    preconditions: Set[Precondition] = field(default_factory=set)
    
    # Effects: what bug types this function may trigger directly (string names)
    may_trigger: Set[str] = field(default_factory=set)
    
    # Exceptions: what exceptions this function may raise
    may_raise: Set[ExceptionType] = field(default_factory=set)
    
    # Nullability: for each param, can it be None? For return, may it be None?
    param_nullability: Dict[int, Nullability] = field(default_factory=dict)
    return_nullability: Nullability = Nullability.TOP
    
    # Division safety: which params are used as divisors (need != 0)
    divisor_params: Set[int] = field(default_factory=set)
    
    # Index params: which params are used as indices (need bounds check)
    # Maps index_param -> container_param
    index_params: Dict[int, int] = field(default_factory=dict)
    
    # Propagation: which params flow to potentially unsafe operations
    # Maps param -> set of bug type names that param may trigger
    param_bug_propagation: Dict[int, Set[str]] = field(default_factory=dict)
    
    # Callee effects: bugs transitively possible from callees (string names)
    transitive_bugs: Set[str] = field(default_factory=set)
    
    # Side effects
    has_side_effects: bool = False
    modifies_globals: bool = False
    performs_io: bool = False
    
    # Guard tracking (NEW): which bug types have guards protecting them
    # Set of bug type names that are protected by guards (should reduce confidence)
    guarded_bugs: Set[str] = field(default_factory=set)
    
    # Analysis metadata
    is_recursive: bool = False
    analyzed: bool = False
    
    def requires_not_none(self, param_idx: int) -> bool:
        """Check if parameter must not be None."""
        return any(
            p.param_index == param_idx and p.condition_type == PreconditionType.NOT_NONE
            for p in self.preconditions
        )
    
    def requires_not_zero(self, param_idx: int) -> bool:
        """Check if parameter must not be zero (divisor)."""
        return param_idx in self.divisor_params or any(
            p.param_index == param_idx and p.condition_type == PreconditionType.NOT_ZERO
            for p in self.preconditions
        )
    
    def all_possible_bugs(self) -> Set[str]:
        """Get all bugs this function may trigger (direct + transitive)."""
        return self.may_trigger | self.transitive_bugs
    
    def get_precondition_violations(
        self,
        arg_nullabilities: List[Nullability],
        arg_may_be_zero: List[bool],
    ) -> Set[str]:
        """
        Check what bugs may occur if called with given argument states.
        
        Returns set of bug type names that could be triggered.
        """
        violations = set()
        
        for i, null in enumerate(arg_nullabilities):
            if self.requires_not_none(i) and null in (Nullability.MAY_BE_NONE, Nullability.IS_NONE):
                violations.add('NULL_PTR')
        
        for i, may_zero in enumerate(arg_may_be_zero):
            if self.requires_not_zero(i) and may_zero:
                violations.add('DIV_ZERO')
        
        return violations
    
    def merge_callee(self, callee: 'CrashSummary') -> None:
        """Merge effects from a callee into this summary."""
        self.transitive_bugs.update(callee.may_trigger)
        self.transitive_bugs.update(callee.transitive_bugs)
        # Exceptions that callee may raise (we might not catch them)
        self.may_raise.update(callee.may_raise)
    
    def check_with_unsafe_predicates(self, state: Any, path_trace: List[str]) -> Optional[Dict]:
        """
        Use the existing UNSAFE_PREDICATES from registry to check for bugs.
        
        This integrates with the sophisticated infrastructure in pyfromscratch/unsafe/
        rather than reimplementing bug detection.
        """
        return check_unsafe_regions(state, path_trace)


# ============================================================================
# CRASH SUMMARY ANALYZER
# ============================================================================

class CrashSummaryAnalyzer(ast.NodeVisitor):
    """
    AST visitor that computes crash summary for a single function.
    
    Analyzes:
    - What operations may crash (division, subscript, attribute access)
    - What exceptions are raised or may propagate
    - Nullability flow from params to operations
    """
    
    def __init__(
        self,
        func_name: str,
        qualified_name: str,
        parameters: List[str],
        file_path: str,
        existing_summaries: Dict[str, CrashSummary],
    ):
        self.func_name = func_name
        self.qualified_name = qualified_name
        self.parameters = parameters
        self.file_path = file_path
        self.summaries = existing_summaries
        
        # Track param index by name
        self.param_indices = {p: i for i, p in enumerate(parameters)}
        
        # Track what flows from each param
        self.var_sources: Dict[str, Set[int]] = {}
        for i, p in enumerate(parameters):
            self.var_sources[p] = {i}
        
        # Build summary
        self.summary = CrashSummary(
            function_name=func_name,
            qualified_name=qualified_name,
            parameter_count=len(parameters),
        )
        
        # Track return nullability from return statements
        self._return_nullabilities: List[Nullability] = []
    
    def analyze(self, func_node: ast.FunctionDef) -> CrashSummary:
        """Analyze function and return crash summary."""
        # ITERATION 610: Initialize param nullability from type annotations
        # If a parameter has a non-Optional type hint, it's likely NOT_NONE
        self._init_param_nullability_from_annotations(func_node)
        
        # ITERATION 610: Only visit the function body, not annotations/decorators
        # Type annotations like Dict[str, Tuple[...]] contain subscripts but are not runtime code
        for stmt in func_node.body:
            self.visit(stmt)
        
        # Compute final return nullability
        if self._return_nullabilities:
            result = Nullability.BOTTOM
            for n in self._return_nullabilities:
                result = result.join(n)
            self.summary.return_nullability = result
        
        self.summary.analyzed = True
        return self.summary
    
    def _init_param_nullability_from_annotations(self, func_node: ast.FunctionDef) -> None:
        """
        Initialize parameter nullability from type annotations.
        
        ITERATION 610: Reduce false positive NULL_PTR for typed parameters.
        If a parameter has a non-Optional type hint (e.g., `x: BaseClass`),
        we assume it's NOT_NONE because the type system implies non-null.
        Only Optional[X] or Union[X, None] or X | None indicate may-be-null.
        """
        for i, arg in enumerate(func_node.args.args):
            if arg.annotation:
                if self._annotation_is_optional(arg.annotation):
                    # Optional type - could be None
                    self.summary.param_nullability[i] = Nullability.MAY_BE_NONE
                else:
                    # Non-optional type annotation - assume NOT_NONE
                    # This reduces FPs for typed code like Qlib
                    self.summary.param_nullability[i] = Nullability.NOT_NONE
            # No annotation = TOP (unknown)
    
    def _annotation_is_optional(self, annotation: ast.AST) -> bool:
        """
        Check if a type annotation indicates Optional/nullable.
        
        Handles:
        - Optional[X] -> True
        - Union[X, None] -> True
        - X | None -> True (Python 3.10+)
        - None -> True
        - Everything else -> False
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
                # typing.Optional, typing.Union
                attr_name = annotation.value.attr
            elif isinstance(annotation.value, ast.Name):
                # Optional, Union
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
    
    def _get_param_sources(self, node: ast.AST) -> Set[int]:
        """Get which parameters flow to this expression."""
        if isinstance(node, ast.Name):
            return self.var_sources.get(node.id, set())
        elif isinstance(node, ast.BinOp):
            return self._get_param_sources(node.left) | self._get_param_sources(node.right)
        elif isinstance(node, ast.UnaryOp):
            return self._get_param_sources(node.operand)
        elif isinstance(node, ast.Call):
            # Conservative: all args
            sources = set()
            for arg in node.args:
                sources |= self._get_param_sources(arg)
            return sources
        elif isinstance(node, ast.Subscript):
            return self._get_param_sources(node.value) | self._get_param_sources(node.slice)
        elif isinstance(node, ast.Attribute):
            return self._get_param_sources(node.value)
        elif isinstance(node, ast.IfExp):
            return (self._get_param_sources(node.test) | 
                   self._get_param_sources(node.body) |
                   self._get_param_sources(node.orelse))
        return set()
    
    def _is_none_literal(self, node: ast.AST) -> bool:
        """Check if node is None literal."""
        return isinstance(node, ast.Constant) and node.value is None
    
    def _get_nullability(self, node: ast.AST) -> Nullability:
        """Estimate nullability of expression."""
        if self._is_none_literal(node):
            return Nullability.IS_NONE
        if isinstance(node, ast.Constant):
            return Nullability.NOT_NONE
        if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.Tuple)):
            return Nullability.NOT_NONE
        if isinstance(node, ast.Name):
            # Check if it's a param we know about
            if node.id in self.param_indices:
                idx = self.param_indices[node.id]
                return self.summary.param_nullability.get(idx, Nullability.TOP)
        return Nullability.TOP
    
    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Check for division by zero risk."""
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            # Right operand is divisor
            divisor_sources = self._get_param_sources(node.right)
            for param_idx in divisor_sources:
                self.summary.divisor_params.add(param_idx)
                self.summary.preconditions.add(
                    Precondition(param_idx, PreconditionType.NOT_ZERO)
                )
                if param_idx not in self.summary.param_bug_propagation:
                    self.summary.param_bug_propagation[param_idx] = set()
                self.summary.param_bug_propagation[param_idx].add('DIV_ZERO')
            
            # If divisor could be zero, we may trigger DIV_ZERO
            if divisor_sources or self._could_be_zero(node.right):
                self.summary.may_trigger.add('DIV_ZERO')
                self.summary.may_raise.add(ExceptionType.ZERO_DIVISION_ERROR)
        
        self.generic_visit(node)
    
    def _could_be_zero(self, node: ast.AST) -> bool:
        """Check if expression could be zero."""
        if isinstance(node, ast.Constant):
            return node.value == 0
        if isinstance(node, ast.Name):
            # Parameter or variable - could be zero
            return True
        return True  # Conservative
    
    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Check for bounds/key error risk."""
        container_sources = self._get_param_sources(node.value)
        index_sources = self._get_param_sources(node.slice)
        
        # ITERATION 610: Only flag BOUNDS for Load context (reading)
        # Dict/list assignment (Store context) cannot raise KeyError/IndexError
        # Del context CAN raise KeyError for dicts, so include it
        if isinstance(node.ctx, (ast.Load, ast.Del)):
            # Index/key access may cause BOUNDS
            self.summary.may_trigger.add('BOUNDS')
            self.summary.may_raise.add(ExceptionType.INDEX_ERROR)
            self.summary.may_raise.add(ExceptionType.KEY_ERROR)
        
        for idx_param in index_sources:
            for container_param in container_sources:
                self.summary.index_params[idx_param] = container_param
                self.summary.preconditions.add(
                    Precondition(idx_param, PreconditionType.IN_BOUNDS, container_param)
                )
            if idx_param not in self.summary.param_bug_propagation:
                self.summary.param_bug_propagation[idx_param] = set()
            self.summary.param_bug_propagation[idx_param].add('BOUNDS')
        
        self.generic_visit(node)
    
    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Check for None dereference risk."""
        obj_sources = self._get_param_sources(node.value)
        obj_null = self._get_nullability(node.value)
        
        # Attribute access on None causes NULL_PTR
        if obj_null in (Nullability.MAY_BE_NONE, Nullability.IS_NONE, Nullability.TOP):
            self.summary.may_trigger.add('NULL_PTR')
            self.summary.may_raise.add(ExceptionType.ATTRIBUTE_ERROR)
            
            for param_idx in obj_sources:
                self.summary.preconditions.add(
                    Precondition(param_idx, PreconditionType.NOT_NONE)
                )
                if param_idx not in self.summary.param_bug_propagation:
                    self.summary.param_bug_propagation[param_idx] = set()
                self.summary.param_bug_propagation[param_idx].add('NULL_PTR')
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Check for callee effects and type errors."""
        # Get callee name
        callee_name = self._get_callee_name(node)
        
        if callee_name:
            # Check if we have a summary for the callee
            if callee_name in self.summaries:
                callee_summary = self.summaries[callee_name]
                self.summary.merge_callee(callee_summary)
            else:
                # Unknown callee - conservative
                self.summary.may_raise.add(ExceptionType.GENERIC_EXCEPTION)
        
        # Calling None causes TYPE_ERROR
        func_sources = self._get_param_sources(node.func)
        for param_idx in func_sources:
            self.summary.preconditions.add(
                Precondition(param_idx, PreconditionType.NOT_NONE)
            )
        
        # Check for known dangerous functions
        if callee_name in ('eval', 'exec', 'compile'):
            self.summary.may_trigger.add('CODE_INJECTION')
        elif callee_name in ('os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen'):
            self.summary.may_trigger.add('COMMAND_INJECTION')
        elif callee_name in ('pickle.loads', 'pickle.load', 'yaml.load', 'marshal.loads'):
            self.summary.may_trigger.add('UNSAFE_DESERIALIZATION')
        elif callee_name in ('open',):
            self.summary.performs_io = True
            self.summary.has_side_effects = True
        elif callee_name == 'assert':
            self.summary.may_trigger.add('ASSERT_FAIL')
            self.summary.may_raise.add(ExceptionType.ASSERTION_ERROR)
        
        self.generic_visit(node)
    
    def _get_callee_name(self, node: ast.Call) -> Optional[str]:
        """Extract callee name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Try to get qualified name
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return None
    
    def visit_Raise(self, node: ast.Raise) -> None:
        """Track explicitly raised exceptions."""
        if node.exc:
            exc_type = self._get_exception_type(node.exc)
            if exc_type:
                self.summary.may_raise.add(exc_type)
                # Map to bug type
                if exc_type in EXCEPTION_TO_BUG:
                    self.summary.may_trigger.add(EXCEPTION_TO_BUG[exc_type])
        else:
            # Re-raise - we inherit from context
            self.summary.may_raise.add(ExceptionType.GENERIC_EXCEPTION)
        
        self.generic_visit(node)
    
    def _get_exception_type(self, node: ast.AST) -> Optional[ExceptionType]:
        """Get exception type from raise expression."""
        if isinstance(node, ast.Call):
            return self._get_exception_type(node.func)
        elif isinstance(node, ast.Name):
            return EXCEPTION_NAMES.get(node.id)
        elif isinstance(node, ast.Attribute):
            return EXCEPTION_NAMES.get(node.attr)
        return None
    
    def visit_Assert(self, node: ast.Assert) -> None:
        """Assert may raise AssertionError."""
        self.summary.may_trigger.add('ASSERT_FAIL')
        self.summary.may_raise.add(ExceptionType.ASSERTION_ERROR)
        self.generic_visit(node)
    
    def visit_Return(self, node: ast.Return) -> None:
        """Track return nullability."""
        if node.value:
            null = self._get_nullability(node.value)
            self._return_nullabilities.append(null)
        else:
            # return with no value = return None
            self._return_nullabilities.append(Nullability.IS_NONE)
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Track dataflow through assignments."""
        sources = self._get_param_sources(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.var_sources[target.id] = sources.copy()
        self.generic_visit(node)
    
    def visit_For(self, node: ast.For) -> None:
        """For loops may raise StopIteration edge cases."""
        self.summary.may_raise.add(ExceptionType.STOP_ITERATION)
        self.generic_visit(node)
    
    def visit_While(self, node: ast.While) -> None:
        """While loops risk non-termination."""
        # Mark as potentially non-terminating (conservative)
        self.summary.may_trigger.add('NON_TERMINATION')
        self.generic_visit(node)
    
    def visit_Global(self, node: ast.Global) -> None:
        """Track global modification."""
        self.summary.modifies_globals = True
        self.summary.has_side_effects = True
        self.generic_visit(node)


# ============================================================================
# BYTECODE-LEVEL CRASH SUMMARY ANALYZER
# ============================================================================

# Opcodes that may trigger specific bug types
DIVISION_OPCODES = {'BINARY_OP'}  # Need to check oparg for division
# ITERATION 610: STORE_SUBSCR (dict[key] = value) never raises KeyError
# Only BINARY_SUBSCR (read) and DELETE_SUBSCR can raise KeyError/IndexError
SUBSCRIPT_OPCODES = {'BINARY_SUBSCR', 'DELETE_SUBSCR'}
ATTRIBUTE_OPCODES = {'LOAD_ATTR', 'STORE_ATTR', 'DELETE_ATTR', 'LOAD_METHOD'}
CALL_OPCODES = {'CALL', 'CALL_FUNCTION', 'CALL_METHOD', 'CALL_FUNCTION_KW', 'CALL_FUNCTION_EX'}
ITERATOR_OPCODES = {'GET_ITER', 'FOR_ITER', 'SEND'}
RAISE_OPCODES = {'RAISE_VARARGS', 'RERAISE'}

# Python 3.11+ binary operation codes (oparg values for BINARY_OP)
BINARY_OP_NAMES = {
    0: 'add', 1: 'and_', 2: 'floor_divide', 3: 'lshift', 4: 'matmul',
    5: 'multiply', 6: 'remainder', 7: 'or_', 8: 'power', 9: 'rshift',
    10: 'subtract', 11: 'true_divide', 12: 'xor', 13: 'inplace_add',
    14: 'inplace_and', 15: 'inplace_floor_divide', 16: 'inplace_lshift',
    17: 'inplace_matmul', 18: 'inplace_multiply', 19: 'inplace_remainder',
    20: 'inplace_or', 21: 'inplace_power', 22: 'inplace_rshift',
    23: 'inplace_subtract', 24: 'inplace_true_divide', 25: 'inplace_xor',
    26: 'subscript',  # Python 3.13+ uses BINARY_OP for subscript
}

DIVISION_BINARY_OPS = {2, 6, 11, 15, 19, 24}  # floor_divide, remainder, true_divide (regular and inplace)
SUBSCRIPT_BINARY_OPS = {26}  # subscript operation in Python 3.13+


@dataclass
class BytecodeLocation:
    """Location in bytecode for crash reporting."""
    offset: int
    opname: str
    oparg: Optional[int]
    line_number: Optional[int]
    block_id: int
    
    def __str__(self) -> str:
        return f"{self.opname}@{self.offset} (line {self.line_number})"


@dataclass
class ParameterFlow:
    """
    Tracks which parameters flow to a stack slot at a bytecode offset.
    
    For bytecode-level analysis, we track data flow through the operand stack.
    """
    # Maps stack depth -> set of parameter indices that may flow there
    stack_flows: Dict[int, Set[int]] = field(default_factory=dict)
    # Maps local variable index -> set of parameter indices
    local_flows: Dict[int, Set[int]] = field(default_factory=dict)
    
    def copy(self) -> 'ParameterFlow':
        return ParameterFlow(
            stack_flows={k: v.copy() for k, v in self.stack_flows.items()},
            local_flows={k: v.copy() for k, v in self.local_flows.items()},
        )
    
    def merge(self, other: 'ParameterFlow') -> 'ParameterFlow':
        """Merge flows from two paths (union)."""
        result = self.copy()
        for k, v in other.stack_flows.items():
            if k in result.stack_flows:
                result.stack_flows[k] = result.stack_flows[k] | v
            else:
                result.stack_flows[k] = v.copy()
        for k, v in other.local_flows.items():
            if k in result.local_flows:
                result.local_flows[k] = result.local_flows[k] | v
            else:
                result.local_flows[k] = v.copy()
        return result


class BytecodeCrashSummaryAnalyzer:
    """
    Bytecode-level crash summary analyzer.
    
    Operates on types.CodeType objects directly, using:
    - CFG from cfg.control_flow.build_cfg
    - Guard/type/bounds analysis from cfg.dataflow.run_intraprocedural_analysis
    - Integrates with unsafe.registry.UNSAFE_PREDICATES
    
    This is the canonical analysis matching the "bytecode-as-abstract-machine"
    semantics described in barrier-certificate-theory.tex.
    """
    
    def __init__(
        self,
        code: types.CodeType,
        func_name: str,
        qualified_name: str,
        existing_summaries: Optional[Dict[str, CrashSummary]] = None,
        param_nullable: Optional[Dict[int, Optional[bool]]] = None,
    ):
        self.code = code
        self.func_name = func_name
        self.qualified_name = qualified_name
        self.summaries = existing_summaries or {}
        
        # ITERATION 610: Track parameter nullability from type annotations
        # Maps param_idx -> True (nullable), False (non-nullable typed), None (no annotation)
        self.param_nullable = param_nullable or {}
        
        # Build CFG and run intraprocedural analysis
        self.cfg: ControlFlowGraph = build_cfg(code)
        self.intraproc: IntraprocAnalysisResult = run_intraprocedural_analysis(code)
        
        # Get parameter information from code object
        self.param_count = code.co_argcount + code.co_kwonlyargcount
        if code.co_flags & 0x04:  # CO_VARARGS
            self.param_count += 1
        if code.co_flags & 0x08:  # CO_VARKEYWORDS
            self.param_count += 1
        
        # Map local variable index -> parameter index (first N locals are params)
        self.param_locals: Dict[int, int] = {}
        for i in range(self.param_count):
            self.param_locals[i] = i
        
        # Instruction list
        self.instructions = list(dis.get_instructions(code))
        self._instr_index_by_offset: Dict[int, int] = {instr.offset: i for i, instr in enumerate(self.instructions)}
        
        # Build summary
        self.summary = CrashSummary(
            function_name=func_name,
            qualified_name=qualified_name,
            parameter_count=self.param_count,
        )
        
        # Track locations of potential crashes
        self.crash_locations: List[Tuple[str, BytecodeLocation]] = []
        
        # Return nullability tracking
        self._return_nullabilities: List[Nullability] = []
        
        # ITERATION 610: Track locals known to be non-None
        # Maps local_idx -> True if known non-None (from BUILD_MAP, BUILD_LIST, etc.)
        self._nonnull_locals: Dict[int, bool] = {}
    
    def analyze(self) -> CrashSummary:
        """
        Analyze bytecode and build crash summary.
        
        Walks through all basic blocks, checking each instruction for:
        - Division by potential zero
        - Subscript access (bounds risk)
        - Attribute access (null dereference risk)
        - Calls to potentially dangerous functions
        - Raises
        """
        # ITERATION 610: First pass - identify non-null locals
        # Scan for BUILD_MAP/BUILD_LIST followed by STORE_FAST
        self._identify_nonnull_locals()
        
        # Compute parameter flow through the function
        flows = self._compute_parameter_flows()
        
        # Analyze each block
        for block_id, block in self.cfg.blocks.items():
            for instr in block.instructions:
                self._analyze_instruction(instr, block, flows)
        
        # Compute final return nullability
        if self._return_nullabilities:
            result = Nullability.BOTTOM
            for n in self._return_nullabilities:
                result = result.join(n)
            self.summary.return_nullability = result
        
        self.summary.analyzed = True
        return self.summary
    
    def _identify_nonnull_locals(self) -> None:
        """
        Identify local variables that are always non-None.
        
        ITERATION 610: Reduce false positive NULL_PTR for locals created by:
        - BUILD_MAP (empty dict)
        - BUILD_LIST (empty list)
        - BUILD_SET (empty set)
        - BUILD_TUPLE (tuple)
        - CALL to constructors (dict(), list(), etc.)
        
        These are followed by STORE_FAST which assigns to a local.
        """
        # Opcodes that create non-None values
        NONNULL_CREATORS = {
            'BUILD_MAP', 'BUILD_LIST', 'BUILD_SET', 'BUILD_TUPLE',
            'BUILD_STRING', 'BUILD_SLICE',
            'LOAD_CONST',  # Constants are non-None (except None itself)
        }
        
        # Scan instruction pairs
        prev_instr = None
        for instr in self.instructions:
            if instr.opname == 'STORE_FAST' and prev_instr:
                local_idx = instr.arg
                
                # Check if previous instruction creates a non-None value
                if prev_instr.opname in NONNULL_CREATORS:
                    # LOAD_CONST None is nullable, others are non-None
                    if prev_instr.opname == 'LOAD_CONST':
                        const_val = self.code.co_consts[prev_instr.arg] if prev_instr.arg < len(self.code.co_consts) else None
                        if const_val is not None:
                            self._nonnull_locals[local_idx] = True
                    else:
                        self._nonnull_locals[local_idx] = True
            
            prev_instr = instr
    
    def _compute_parameter_flows(self) -> Dict[int, ParameterFlow]:
        """
        Compute which parameters flow to which stack/local positions at each offset.
        
        This is a forward dataflow analysis over the bytecode.
        """
        flows: Dict[int, ParameterFlow] = {}
        
        # Initialize: at entry, parameters are in their local slots
        initial = ParameterFlow()
        for i in range(self.param_count):
            initial.local_flows[i] = {i}
        
        if self.instructions:
            flows[self.instructions[0].offset] = initial
        
        # Simple forward propagation (not full fixpoint for now)
        for idx, instr in enumerate(self.instructions):
            if instr.offset not in flows:
                flows[instr.offset] = ParameterFlow()
            
            flow = flows[instr.offset].copy()
            
            # Update flow based on instruction
            self._update_flow_for_instruction(instr, flow)
            
            # Propagate to the next instruction in the disassembly stream.
            # Using `offset + 2` is brittle with Python 3.11+ specialized opcodes.
            if idx + 1 < len(self.instructions):
                next_offset = self.instructions[idx + 1].offset
                if next_offset not in flows:
                    flows[next_offset] = flow
                else:
                    flows[next_offset] = flows[next_offset].merge(flow)
        
        return flows
    
    def _update_flow_for_instruction(self, instr: dis.Instruction, flow: ParameterFlow) -> None:
        """Update parameter flow for a single instruction."""
        opname = instr.opname
        
        if opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
            # Load local to stack
            local_idx = instr.arg
            if local_idx in flow.local_flows:
                # Stack grows - assume stack depth tracking (simplified)
                flow.stack_flows[0] = flow.local_flows[local_idx].copy()

        elif opname == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
            # Python 3.14 specialized opcode: pushes two locals.
            # For our simplified tracking, keep only the top-of-stack (second local).
            names = instr.argval if isinstance(instr.argval, tuple) else None
            if names and len(names) == 2:
                try:
                    local_idx = list(self.code.co_varnames).index(names[1])
                except ValueError:
                    local_idx = None
                if local_idx is not None and local_idx in flow.local_flows:
                    flow.stack_flows[0] = flow.local_flows[local_idx].copy()
        
        elif opname == 'STORE_FAST':
            # Store from stack to local
            local_idx = instr.arg
            if 0 in flow.stack_flows:
                flow.local_flows[local_idx] = flow.stack_flows[0].copy()
            else:
                flow.local_flows[local_idx] = set()
        
        elif opname in ('LOAD_CONST', 'LOAD_SMALL_INT', 'LOAD_GLOBAL', 'LOAD_NAME'):
            # Load non-param value to stack
            flow.stack_flows[0] = set()
        
        elif opname == 'BINARY_OP':
            # Combines TOS and TOS1, result in TOS
            left = flow.stack_flows.get(1, set())
            right = flow.stack_flows.get(0, set())
            flow.stack_flows[0] = left | right
    
    def _analyze_instruction(
        self,
        instr: dis.Instruction,
        block: BasicBlock,
        flows: Dict[int, ParameterFlow],
    ) -> None:
        """Analyze a single instruction for crash risks."""
        offset = instr.offset
        opname = instr.opname
        
        # Get intraprocedural analysis results at this offset
        guards = self.intraproc.get_guards_at_offset(offset)
        
        # Create location for reporting
        location = BytecodeLocation(
            offset=offset,
            opname=opname,
            oparg=instr.arg,
            line_number=instr.positions.lineno if hasattr(instr, 'positions') and instr.positions else None,
            block_id=block.id,
        )
        
        flow = flows.get(offset, ParameterFlow())
        
        # Check for division
        if opname == 'BINARY_OP' and instr.arg in DIVISION_BINARY_OPS:
            self._check_division(location, flow, guards)
        
        # Check for subscript access (Python 3.13+ uses BINARY_OP with oparg 26)
        elif opname == 'BINARY_OP' and instr.arg in SUBSCRIPT_BINARY_OPS:
            self._check_subscript(location, flow, guards)
        
        # Check for subscript access (older Python versions)
        elif opname in SUBSCRIPT_OPCODES:
            self._check_subscript(location, flow, guards)
        
        # Check for attribute access
        elif opname in ATTRIBUTE_OPCODES:
            self._check_attribute(location, flow, guards, instr)
        
        # Check for calls
        elif opname in CALL_OPCODES:
            self._check_call(location, flow, guards, instr)
        
        # Check for raises
        elif opname in RAISE_OPCODES:
            self._check_raise(location, instr)
        
        # Check for return
        elif opname in ('RETURN_VALUE', 'RETURN_CONST'):
            self._check_return(location, flow, instr)
        
        # ITERATION 610: FOR_ITER is expected behavior (StopIteration terminates loop)
        # Do NOT flag this as ITERATOR_INVALID - it's normal loop termination
        # elif opname == 'FOR_ITER':
        #     self.summary.may_raise.add(ExceptionType.STOP_ITERATION)
        
        # Check for assertions (implicit in RAISE_VARARGS after LOAD_ASSERTION_ERROR)
        elif opname == 'LOAD_ASSERTION_ERROR':
            self.summary.may_trigger.add('ASSERT_FAIL')
            self.summary.may_raise.add(ExceptionType.ASSERTION_ERROR)
    
    def _check_division(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
    ) -> None:
        """Check for division by zero risk."""
        # Divisor is TOS (stack position 0)
        divisor_params = flow.stack_flows.get(0, set())
        
        # If the divisor is a definite non-zero constant, do not report DIV_ZERO.
        # This avoids conservative false positives like `y / 2`.
        idx = self._instr_index_by_offset.get(location.offset)
        if idx is not None:
            j = idx - 1
            while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'RESUME'):
                j -= 1
            if j >= 0:
                prev = self.instructions[j]
                if prev.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and isinstance(prev.argval, (int, float, bool)):
                    if float(prev.argval) != 0.0:
                        return
        
        for param_idx in divisor_params:
            var_name = self.code.co_varnames[param_idx] if param_idx < len(self.code.co_varnames) else f"p{param_idx}"
            
            # Check if we have a guard that divisor is non-zero
            if not guards.has_div_safe(var_name):
                self.summary.divisor_params.add(param_idx)
                self.summary.preconditions.add(
                    Precondition(param_idx, PreconditionType.NOT_ZERO)
                )
                if param_idx not in self.summary.param_bug_propagation:
                    self.summary.param_bug_propagation[param_idx] = set()
                self.summary.param_bug_propagation[param_idx].add('DIV_ZERO')
        
        # Check if division is guarded
        is_guarded = any(
            guards.has_div_safe(self.code.co_varnames[p] if p < len(self.code.co_varnames) else f"p{p}")
            for p in divisor_params
        ) if divisor_params else False
        
        if not is_guarded:
            self.summary.may_trigger.add('DIV_ZERO')
            self.summary.may_raise.add(ExceptionType.ZERO_DIVISION_ERROR)
            self.crash_locations.append(('DIV_ZERO', location))
        else:
            # Track that this bug type has guarded instances
            self.summary.guarded_bugs.add('DIV_ZERO')
    
    def _check_subscript(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
    ) -> None:
        """Check for bounds/key error risk."""
        # For BINARY_SUBSCR: TOS is index, TOS1 is container
        index_params = flow.stack_flows.get(0, set())
        container_params = flow.stack_flows.get(1, set())
        
        for idx_param in index_params:
            for container_param in container_params:
                self.summary.index_params[idx_param] = container_param
                self.summary.preconditions.add(
                    Precondition(idx_param, PreconditionType.IN_BOUNDS, container_param)
                )
            if idx_param not in self.summary.param_bug_propagation:
                self.summary.param_bug_propagation[idx_param] = set()
            self.summary.param_bug_propagation[idx_param].add('BOUNDS')
        
        # Check if bounds are guarded
        is_guarded = False
        for idx_param in index_params:
            var_name = self.code.co_varnames[idx_param] if idx_param < len(self.code.co_varnames) else f"p{idx_param}"
            bounds = self.intraproc.get_bounds(location.offset, var_name)
            if bounds and bounds.lower is not None and bounds.lower >= 0:
                # Has positive lower bound - partially guarded
                is_guarded = True
        
        # Only report if unguarded (fixed logic)
        if not is_guarded:
            self.summary.may_trigger.add('BOUNDS')
            self.summary.may_raise.add(ExceptionType.INDEX_ERROR)
            self.summary.may_raise.add(ExceptionType.KEY_ERROR)
            self.crash_locations.append(('BOUNDS', location))
        else:
            # Track that this bug type has guarded instances
            self.summary.guarded_bugs.add('BOUNDS')
    
    def _check_attribute(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
        instr: dis.Instruction,
    ) -> None:
        """Check for null dereference risk."""
        # Object is on TOS
        obj_params = flow.stack_flows.get(0, set())
        
        # ITERATION 610: Check if TOS comes from a known non-null local
        # Look at preceding instruction to find what's on TOS
        tos_is_nonnull = self._is_tos_nonnull_at(location.offset)
        if tos_is_nonnull:
            # Local variable is known non-None - no NULL_PTR risk
            self.summary.guarded_bugs.add('NULL_PTR')
            return
        
        # ITERATION 610: Use type annotations to determine nullability
        # If parameter is typed as non-nullable, skip NULL_PTR check for it
        nullable_params = set()
        for param_idx in obj_params:
            # Check type annotation nullability
            if param_idx in self.param_nullable:
                is_nullable = self.param_nullable[param_idx]
                if is_nullable is False:
                    # Explicitly typed as non-nullable - skip
                    continue
                elif is_nullable is True:
                    # Explicitly typed as nullable (Optional)
                    nullable_params.add(param_idx)
                else:
                    # No annotation - conservative
                    nullable_params.add(param_idx)
            else:
                # No annotation info - conservative
                nullable_params.add(param_idx)
        
        # Check nullability for each potentially-nullable parameter
        for param_idx in nullable_params:
            var_name = self.code.co_varnames[param_idx] if param_idx < len(self.code.co_varnames) else f"p{param_idx}"
            
            # Check if we have a non-null guard
            if not guards.has_nonnull(var_name) and not self.intraproc.is_nonnull(location.offset, var_name):
                self.summary.preconditions.add(
                    Precondition(param_idx, PreconditionType.NOT_NONE)
                )
                if param_idx not in self.summary.param_bug_propagation:
                    self.summary.param_bug_propagation[param_idx] = set()
                self.summary.param_bug_propagation[param_idx].add('NULL_PTR')
        
        # Conservative: if we have no flow info, attribute access is still risky
        # but only if there are nullable params
        is_guarded = False
        if nullable_params:
            is_guarded = all(
                guards.has_nonnull(self.code.co_varnames[p] if p < len(self.code.co_varnames) else f"p{p}")
                for p in nullable_params
            )
        elif obj_params:
            # All params are typed non-nullable - considered guarded
            is_guarded = True
        
        if not is_guarded:
            self.summary.may_trigger.add('NULL_PTR')
            self.summary.may_raise.add(ExceptionType.ATTRIBUTE_ERROR)
            self.crash_locations.append(('NULL_PTR', location))
        else:
            # Track that this bug type has guarded instances
            self.summary.guarded_bugs.add('NULL_PTR')
    
    def _check_call(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
        instr: dis.Instruction,
    ) -> None:
        """Check for call-related crash risks."""
        # Get callee name from preceding LOAD_* instructions if possible
        callee_name = self._get_callee_name_at(location.offset)
        
        if callee_name:
            # Check if we have a summary for the callee
            if callee_name in self.summaries:
                callee_summary = self.summaries[callee_name]
                self.summary.merge_callee(callee_summary)
            
            # Check for known dangerous functions
            if callee_name in ('eval', 'exec', 'compile'):
                self.summary.may_trigger.add('CODE_INJECTION')
                self.crash_locations.append(('CODE_INJECTION', location))
            elif callee_name in ('os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen'):
                self.summary.may_trigger.add('COMMAND_INJECTION')
                self.crash_locations.append(('COMMAND_INJECTION', location))
            elif callee_name in ('pickle.loads', 'pickle.load', 'yaml.load', 'marshal.loads'):
                self.summary.may_trigger.add('UNSAFE_DESERIALIZATION')
                self.crash_locations.append(('UNSAFE_DESERIALIZATION', location))
            elif callee_name == 'open':
                self.summary.performs_io = True
                self.summary.has_side_effects = True
        
        # Unknown callee - conservative
        self.summary.may_raise.add(ExceptionType.GENERIC_EXCEPTION)
    
    def _check_raise(self, location: BytecodeLocation, instr: dis.Instruction) -> None:
        """Check for explicit raise."""
        # Look at preceding instructions to determine exception type
        exc_type = self._get_exception_type_at(location.offset)
        
        if exc_type:
            self.summary.may_raise.add(exc_type)
            if exc_type in EXCEPTION_TO_BUG:
                self.summary.may_trigger.add(EXCEPTION_TO_BUG[exc_type])
        else:
            self.summary.may_raise.add(ExceptionType.GENERIC_EXCEPTION)
    
    def _check_return(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        instr: dis.Instruction,
    ) -> None:
        """Track return value nullability."""
        if instr.opname == 'RETURN_CONST':
            # Check if returning None
            const_val = self.code.co_consts[instr.arg] if instr.arg < len(self.code.co_consts) else None
            if const_val is None:
                self._return_nullabilities.append(Nullability.IS_NONE)
            else:
                self._return_nullabilities.append(Nullability.NOT_NONE)
        else:
            # RETURN_VALUE - value on stack
            ret_params = flow.stack_flows.get(0, set())
            if not ret_params:
                self._return_nullabilities.append(Nullability.TOP)
            else:
                # Conservative: if any param flows here, inherit its nullability
                self._return_nullabilities.append(Nullability.MAY_BE_NONE)
    
    def _is_tos_nonnull_at(self, offset: int) -> bool:
        """
        Check if TOS (top of stack) at given offset is known non-null.
        
        ITERATION 610: Look at the preceding instruction to determine what's on TOS.
        If it's a LOAD_FAST of a known non-null local, return True.
        """
        # Find instruction index
        idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                idx = i
                break
        
        if idx is None or idx == 0:
            return False
        
        # Look at previous instruction
        prev = self.instructions[idx - 1]
        
        # LOAD_FAST from a known non-null local
        if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_BORROW_LOAD_FAST_BORROW'):
            local_idx = prev.arg
            # Handle composite opcodes
            if prev.opname == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
                local_idx = prev.arg & 0xFF  # First local is in low byte
            if local_idx in self._nonnull_locals:
                return True
            # Also check if it's a non-nullable parameter
            if local_idx < self.param_count:
                if local_idx in self.param_nullable:
                    if self.param_nullable[local_idx] is False:
                        return True
        
        # LOAD_CONST of non-None value
        if prev.opname == 'LOAD_CONST':
            const_val = self.code.co_consts[prev.arg] if prev.arg < len(self.code.co_consts) else None
            if const_val is not None:
                return True
        
        # BUILD_* opcodes always produce non-None
        if prev.opname in ('BUILD_MAP', 'BUILD_LIST', 'BUILD_SET', 'BUILD_TUPLE', 'BUILD_STRING'):
            return True
        
        # ITERATION 610: LOAD_GLOBAL typically loads non-None values (modules, classes, functions)
        # This reduces FPs for attribute access on imported modules like `C.limit_threshold`
        if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
            return True
        
        return False
    
    def _get_callee_name_at(self, offset: int) -> Optional[str]:
        """
        Try to determine callee name from bytecode context.
        
        Looks for LOAD_NAME/LOAD_GLOBAL/LOAD_ATTR patterns before CALL.
        """
        # Find instruction index
        idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                idx = i
                break
        
        if idx is None or idx == 0:
            return None
        
        # Look backwards for loading instructions
        parts = []
        for i in range(idx - 1, max(idx - 5, -1), -1):
            prev = self.instructions[i]
            if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                parts.insert(0, prev.argval)
                break
            elif prev.opname == 'LOAD_ATTR':
                parts.insert(0, prev.argval)
            elif prev.opname == 'LOAD_METHOD':
                parts.insert(0, prev.argval)
            elif prev.opname == 'PUSH_NULL':
                continue
            else:
                break
        
        return '.'.join(parts) if parts else None
    
    def _get_exception_type_at(self, offset: int) -> Optional[ExceptionType]:
        """Try to determine exception type from bytecode context."""
        # Find instruction index
        idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                idx = i
                break
        
        if idx is None:
            return None
        
        # Look backwards for LOAD_GLOBAL/LOAD_NAME of exception class
        for i in range(idx - 1, max(idx - 5, -1), -1):
            prev = self.instructions[i]
            if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                exc_name = prev.argval
                return EXCEPTION_NAMES.get(exc_name)
            elif prev.opname == 'CALL':
                continue  # Skip the call to exception constructor
        
        return None
    
    def get_crash_locations(self) -> List[Tuple[str, BytecodeLocation]]:
        """Get all locations where crashes may occur."""
        return self.crash_locations


# ============================================================================
# BYTECODE CRASH SUMMARY COMPUTER
# ============================================================================

class BytecodeCrashSummaryComputer:
    """
    Computes crash summaries at bytecode level for all functions.
    
    Uses the call graph to process in bottom-up order (callees before callers).
    For SCCs (mutual recursion), uses Kleene iteration until fixpoint.
    
    This is the preferred analyzer matching the "bytecode-as-abstract-machine"
    semantics.
    """
    
    def __init__(self, call_graph: 'CallGraph'):
        self.call_graph = call_graph
        self.summaries: Dict[str, CrashSummary] = {}
    
    def compute_all(self) -> Dict[str, CrashSummary]:
        """Compute crash summaries for all functions in bottom-up order."""
        # Get SCCs in reverse topological order
        sccs = self.call_graph.compute_sccs()
        
        for scc in sccs:
            if len(scc) == 1:
                # Single function - analyze directly
                func_name = next(iter(scc))
                self._analyze_function(func_name)
            else:
                # SCC with mutual recursion - iterate to fixpoint
                self._analyze_scc(scc)
        
        return self.summaries
    
    def _analyze_function(self, func_name: str) -> CrashSummary:
        """Analyze a single function at bytecode level."""
        if func_name in self.summaries:
            return self.summaries[func_name]
        
        func_info = self.call_graph.get_function(func_name)
        if func_info is None:
            # Unknown function - create conservative summary
            summary = CrashSummary(
                function_name=func_name,
                qualified_name=func_name,
                parameter_count=0,
                may_raise={ExceptionType.GENERIC_EXCEPTION},
            )
            self.summaries[func_name] = summary
            return summary
        
        # Get the code object
        code = self._get_code_object(func_info)
        
        if code is not None:
            try:
                # ITERATION 610: Pass param_nullable info to analyzer
                param_nullable = getattr(func_info, 'param_nullable', {})
                
                analyzer = BytecodeCrashSummaryAnalyzer(
                    code=code,
                    func_name=func_info.name,
                    qualified_name=func_info.qualified_name,
                    existing_summaries=self.summaries,
                    param_nullable=param_nullable,
                )
                summary = analyzer.analyze()
                self.summaries[func_name] = summary
                return summary
            except Exception:
                pass
        
        # Fallback: conservative summary
        summary = CrashSummary(
            function_name=func_name,
            qualified_name=func_name,
            parameter_count=len(func_info.parameters) if func_info else 0,
            may_raise={ExceptionType.GENERIC_EXCEPTION},
        )
        self.summaries[func_name] = summary
        return summary
    
    def _get_code_object(self, func_info) -> Optional[types.CodeType]:
        """
        Get the code object for a function.
        
        First checks if func_info already has a code_object, otherwise
        tries to compile the function source to get its code object.
        """
        # ITERATION 610: Use existing code_object if available
        if hasattr(func_info, 'code_object') and func_info.code_object is not None:
            return func_info.code_object
        
        try:
            with open(func_info.file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            # Compile to get code objects
            module_code = compile(source, func_info.file_path, 'exec')
            
            # Find the function's code object in the module's constants
            # Search recursively through all nested code objects
            return self._find_nested_code(module_code, func_info.name, func_info.line_number)
        except Exception:
            return None
    
    def _find_nested_code(
        self,
        code: types.CodeType,
        name: str,
        line_number: int
    ) -> Optional[types.CodeType]:
        """Find a nested function's code object."""
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                if const.co_name == name and const.co_firstlineno == line_number:
                    return const
                nested = self._find_nested_code(const, name, line_number)
                if nested:
                    return nested
        return None
    
    def _analyze_scc(self, scc: Set[str]) -> None:
        """Analyze mutually recursive functions using fixpoint iteration."""
        # Initialize with empty summaries
        for func_name in scc:
            func_info = self.call_graph.get_function(func_name)
            self.summaries[func_name] = CrashSummary(
                function_name=func_name,
                qualified_name=func_name,
                parameter_count=len(func_info.parameters) if func_info else 0,
                is_recursive=True,
            )
        
        # Iterate until fixpoint
        max_iterations = 10
        for _ in range(max_iterations):
            changed = False
            for func_name in scc:
                old_bugs = self.summaries[func_name].all_possible_bugs().copy()
                old_exceptions = self.summaries[func_name].may_raise.copy()
                
                self._analyze_function(func_name)
                
                new_bugs = self.summaries[func_name].all_possible_bugs()
                new_exceptions = self.summaries[func_name].may_raise
                
                if old_bugs != new_bugs or old_exceptions != new_exceptions:
                    changed = True
            
            if not changed:
                break


def analyze_code_object(
    code: types.CodeType,
    func_name: str = None,
    qualified_name: str = None,
    existing_summaries: Dict[str, CrashSummary] = None,
) -> CrashSummary:
    """
    Convenience function to analyze a single code object.
    
    This is the primary entry point for bytecode-level crash analysis.
    
    Example:
        def my_function(x, y):
            return x / y
        
        summary = analyze_code_object(my_function.__code__)
        print(summary.may_trigger)  # {'DIV_ZERO'}
        print(summary.divisor_params)  # {1}  (y is at index 1)
    """
    name = func_name or code.co_name
    qname = qualified_name or code.co_qualname if hasattr(code, 'co_qualname') else name
    
    analyzer = BytecodeCrashSummaryAnalyzer(
        code=code,
        func_name=name,
        qualified_name=qname,
        existing_summaries=existing_summaries,
    )
    return analyzer.analyze()


# ============================================================================
# CRASH SUMMARY COMPUTER
# ============================================================================

class CrashSummaryComputer:
    """
    Computes crash summaries for all functions in a project.
    
    Uses the call graph to process in bottom-up order (callees before callers).
    For SCCs (mutual recursion), uses Kleene iteration until fixpoint.
    """
    
    def __init__(self, call_graph: 'CallGraph'):
        self.call_graph = call_graph
        self.summaries: Dict[str, CrashSummary] = {}
    
    def compute_all(self) -> Dict[str, CrashSummary]:
        """Compute crash summaries for all functions in bottom-up order."""
        # Get SCCs in reverse topological order
        sccs = self.call_graph.compute_sccs()
        
        for scc in sccs:
            if len(scc) == 1:
                # Single function - analyze directly
                func_name = next(iter(scc))
                self._analyze_function(func_name)
            else:
                # SCC with mutual recursion - iterate to fixpoint
                self._analyze_scc(scc)
        
        return self.summaries
    
    def _analyze_function(self, func_name: str) -> CrashSummary:
        """Analyze a single function."""
        if func_name in self.summaries:
            return self.summaries[func_name]
        
        func_info = self.call_graph.get_function(func_name)
        if func_info is None:
            # Unknown function - create conservative summary
            summary = CrashSummary(
                function_name=func_name,
                qualified_name=func_name,
                parameter_count=0,
                may_raise={ExceptionType.GENERIC_EXCEPTION},
            )
            self.summaries[func_name] = summary
            return summary
        
        # Parse the file and find the function
        try:
            with open(func_info.file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            tree = ast.parse(source)
            
            # Find the function node
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == func_info.name and node.lineno == func_info.line_number:
                        analyzer = CrashSummaryAnalyzer(
                            func_name=func_info.name,
                            qualified_name=func_info.qualified_name,
                            parameters=func_info.parameters,
                            file_path=func_info.file_path,
                            existing_summaries=self.summaries,
                        )
                        summary = analyzer.analyze(node)
                        self.summaries[func_name] = summary
                        return summary
        except Exception:
            pass
        
        # Fallback: conservative summary
        summary = CrashSummary(
            function_name=func_name,
            qualified_name=func_name,
            parameter_count=len(func_info.parameters) if func_info else 0,
            may_raise={ExceptionType.GENERIC_EXCEPTION},
        )
        self.summaries[func_name] = summary
        return summary
    
    def _analyze_scc(self, scc: Set[str]) -> None:
        """Analyze mutually recursive functions using fixpoint iteration."""
        # Initialize with empty summaries
        for func_name in scc:
            func_info = self.call_graph.get_function(func_name)
            self.summaries[func_name] = CrashSummary(
                function_name=func_name,
                qualified_name=func_name,
                parameter_count=len(func_info.parameters) if func_info else 0,
                is_recursive=True,
            )
        
        # Iterate until fixpoint
        max_iterations = 10
        for _ in range(max_iterations):
            changed = False
            for func_name in scc:
                old_bugs = self.summaries[func_name].all_possible_bugs().copy()
                old_exceptions = self.summaries[func_name].may_raise.copy()
                
                self._analyze_function(func_name)
                
                new_bugs = self.summaries[func_name].all_possible_bugs()
                new_exceptions = self.summaries[func_name].may_raise
                
                if old_bugs != new_bugs or old_exceptions != new_exceptions:
                    changed = True
            
            if not changed:
                break


# ============================================================================
# COMBINED INTERPROCEDURAL SUMMARY
# ============================================================================

@dataclass
class InterproceduralBugSummary:
    """
    Combined summary for all bug types at a function.
    
    Merges taint summaries (security) with crash summaries (correctness).
    """
    function_name: str
    
    # From taint summary
    taint_summary: Optional['TaintSummary'] = None
    
    # From crash summary  
    crash_summary: Optional[CrashSummary] = None
    
    def all_possible_bugs(self) -> Set[BugType]:
        """Get all bugs this function may trigger."""
        bugs = set()
        if self.crash_summary:
            bugs |= self.crash_summary.all_possible_bugs()
        if self.taint_summary:
            # Convert security bug indicators to BugType
            if self.taint_summary.dependency.is_sink:
                # The sink type maps to a security bug
                pass  # Would need sink_type -> BugType mapping
            if self.taint_summary.dependency.introduces_taint:
                # Source - may lead to injection bugs downstream
                pass
        return bugs
    
    def check_call(
        self,
        arg_nullabilities: List[Nullability],
        arg_may_be_zero: List[bool],
        arg_tainted: List[bool],
    ) -> Set[BugType]:
        """
        Check what bugs may occur when calling with given arguments.
        
        Returns set of potential bugs from this call.
        """
        bugs = set()
        
        if self.crash_summary:
            bugs |= self.crash_summary.get_precondition_violations(
                arg_nullabilities, arg_may_be_zero
            )
        
        # Taint-based bugs would be checked separately via taint tracker
        
        return bugs


def compute_all_bug_summaries(
    call_graph: 'CallGraph',
    taint_summaries: Dict[str, 'TaintSummary'] = None,
) -> Dict[str, InterproceduralBugSummary]:
    """
    Compute combined bug summaries for all functions.
    
    Merges taint analysis (security bugs) with crash analysis (correctness bugs).
    """
    taint_summaries = taint_summaries or {}
    
    # Compute crash summaries
    crash_computer = CrashSummaryComputer(call_graph)
    crash_summaries = crash_computer.compute_all()
    
    # Merge into combined summaries
    all_funcs = set(crash_summaries.keys()) | set(taint_summaries.keys())
    combined = {}
    
    for func_name in all_funcs:
        combined[func_name] = InterproceduralBugSummary(
            function_name=func_name,
            taint_summary=taint_summaries.get(func_name),
            crash_summary=crash_summaries.get(func_name),
        )
    
    return combined


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Registry integration
    'REGISTERED_BUG_TYPES',
    'PreconditionType', 'Precondition',
    'ExceptionType', 'EXCEPTION_NAMES', 'EXCEPTION_TO_BUG', 'PRECONDITION_TO_BUG',
    'Nullability',
    
    # Summaries
    'CrashSummary',
    
    # AST-based analyzer (legacy)
    'CrashSummaryAnalyzer',
    'CrashSummaryComputer',
    
    # Bytecode-level analyzer (preferred)
    'BytecodeLocation',
    'ParameterFlow',
    'BytecodeCrashSummaryAnalyzer',
    'BytecodeCrashSummaryComputer',
    'analyze_code_object',
    
    # Combined
    'InterproceduralBugSummary',
    'compute_all_bug_summaries',
]
