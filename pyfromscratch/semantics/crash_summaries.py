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
from ..cfg.control_flow import build_cfg, ControlFlowGraph, GuardAnalyzer, BasicBlock
from ..cfg.control_flow import build_cfg, ControlFlowGraph, BasicBlock, ExceptionCatchAnalyzer

# Bug type names from the registry (canonical source of truth)
REGISTERED_BUG_TYPES: List[str] = list_implemented_bug_types()


# Exception types that guard specific bugs
# Maps bug type name to the exceptions that catch it
EXCEPTION_BARRIER_MAP: Dict[str, List[str]] = {
    'DIV_ZERO': ['ZeroDivisionError'],
    'BOUNDS': ['IndexError', 'KeyError'],
    'NULL_PTR': ['AttributeError', 'TypeError'],
    'VALUE_ERROR': ['ValueError'],
    'TYPE_CONFUSION': ['TypeError'],
}


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


# ============================================================================
# GUARD TRACKING FOR FALSE POSITIVE REDUCTION
# ============================================================================

@dataclass
class GuardTracker:
    """
    Track guards that dominate the current program point.
    
    From barrier-certificate-theory.tex, guards are derived from control flow
    and semantic facts. A bug is only real if reachable with guards = 0.
    
    Key insight: B(s) >= 0 incorporates guards; safety is B >= 0 on all reachable states.
    If g_nonnull(x) = 1 dominates an access x.attr, then that access is safe.
    """
    # Variables known to be non-None on current path
    nonnull_vars: Set[str] = field(default_factory=set)
    # Variables known to be non-zero on current path
    nonzero_vars: Set[str] = field(default_factory=set)
    # Containers known to be non-empty on current path
    nonempty_vars: Set[str] = field(default_factory=set)
    # Variables with known types
    typed_vars: Dict[str, str] = field(default_factory=dict)
    # Loop iteration variables: var -> container they iterate
    loop_vars: Dict[str, str] = field(default_factory=dict)
    # Whether we're inside a try block that catches relevant exceptions
    exception_handlers: Set[str] = field(default_factory=set)
    
    def copy(self) -> 'GuardTracker':
        """Create a copy for branching."""
        return GuardTracker(
            nonnull_vars=self.nonnull_vars.copy(),
            nonzero_vars=self.nonzero_vars.copy(),
            nonempty_vars=self.nonempty_vars.copy(),
            typed_vars=self.typed_vars.copy(),
            loop_vars=self.loop_vars.copy(),
            exception_handlers=self.exception_handlers.copy(),
        )
    
    def is_guarded_nonnull(self, var: str) -> bool:
        """Check if variable is guarded as non-None."""
        return var in self.nonnull_vars
    
    def is_guarded_nonzero(self, var: str) -> bool:
        """Check if variable is guarded as non-zero."""
        return var in self.nonzero_vars
    
    def is_guarded_nonempty(self, container: str) -> bool:
        """Check if container is guarded as non-empty."""
        return container in self.nonempty_vars
    
    def is_safe_loop_index(self, index_var: str, container_var: str) -> bool:
        """Check if index is from iteration over the same container."""
        return self.loop_vars.get(index_var) == container_var


# ============================================================================
# DSE-BASED ANALYSIS: NO AD-HOC NAME HEURISTICS
# ============================================================================
# REMOVED: NEVER_NONE_NAMES, PATH_RELATED_NAMES
# 
# Instead of name-based heuristics, use:
# 1. SymbolicVM with Z3 for reachability checking
# 2. GuardDataflowAnalysis for guard propagation through CFG
# 3. Type annotations and inference for nullability
# 4. Barrier certificate synthesis for safety proofs
#
# See: dse_bug_detector.py for proper DSE-based analysis
# ============================================================================


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
# ITERATION 700: Fine-grained exception mapping instead of just PANIC
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
    # Fine-grained exception types (ITERATION 700)
    ExceptionType.VALUE_ERROR: 'VALUE_ERROR',
    ExceptionType.RUNTIME_ERROR: 'RUNTIME_ERROR',
    ExceptionType.FILE_NOT_FOUND_ERROR: 'FILE_NOT_FOUND',
    ExceptionType.PERMISSION_ERROR: 'PERMISSION_ERROR',
    ExceptionType.OS_ERROR: 'OS_ERROR',
    ExceptionType.IO_ERROR: 'IO_ERROR',
    ExceptionType.IMPORT_ERROR: 'IMPORT_ERROR',
    ExceptionType.NAME_ERROR: 'NAME_ERROR',
    ExceptionType.UNBOUND_LOCAL_ERROR: 'UNBOUND_LOCAL',
    ExceptionType.TIMEOUT_ERROR: 'TIMEOUT_ERROR',
    ExceptionType.GENERIC_EXCEPTION: 'PANIC',  # Only truly custom exceptions
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
    
    # ITERATION 702: Per-instance guard tracking for accurate FP counting
    # Tracks counts of guarded vs unguarded instances per bug type
    # bug_type -> (guarded_count, unguarded_count)
    guard_counts: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    
    # INTERPROCEDURAL GUARD EXTENSION: Track return value and param guarantees
    # These enable FP reduction across function boundaries
    # Return guarantees: what this function guarantees about its return value
    return_guarantees: Set[str] = field(default_factory=set)  # e.g., {'nonnull', 'nonzero'}
    # Param validation: which params are validated (callers can trust them)
    validated_params: Dict[int, Set[str]] = field(default_factory=dict)  # param_idx -> {'nonnull', 'nonempty', ...}
    
    # INTRAPROCEDURAL GUARD FACTS: Raw guard facts from GuardAnalyzer
    # These are automatically propagated to interprocedural analysis
    # Maps block_id -> set of guard type strings established at that block
    # This allows any guard pattern in control_flow.py to be used interprocedurally
    intra_guard_facts: Dict[int, Set[Tuple[str, str, Optional[str]]]] = field(default_factory=dict)
    # Aggregated guard types for quick lookup: guard_type -> set of variables
    guard_type_to_vars: Dict[str, Set[str]] = field(default_factory=dict)
    
    # VALUE FLOW TRACKING: Track which variables hold the same value (aliasing)
    # This enables guard propagation through assignments:
    #   if x is not None:  # guard on x
    #       y = x          # y now aliases x
    #       y.attr         # bug on y, but guarded through alias to x
    # Maps variable -> set of variables that hold the same value
    value_aliases: Dict[str, Set[str]] = field(default_factory=dict)
    
    # BYTECODE INSTRUCTIONS: Store for barrier-theoretic stdlib detection
    # This enables Papers #9-12 (ICE), #13-16 (IC3), #17-20 (CHC) to analyze
    # stdlib usage patterns and synthesize barriers
    bytecode_instructions: List[Any] = field(default_factory=list)
    
    # Analysis metadata
    is_recursive: bool = False
    analyzed: bool = False
    
    def add_guard_fact(self, guard_type: str, variable: str, extra: Optional[str] = None, block_id: int = 0) -> None:
        """
        Add a guard fact from intraprocedural analysis.
        
        This is called by BytecodeCrashSummaryAnalyzer to store guard facts
        that can be used interprocedurally.
        """
        if block_id not in self.intra_guard_facts:
            self.intra_guard_facts[block_id] = set()
        self.intra_guard_facts[block_id].add((guard_type, variable, extra))
        
        # Also update the quick lookup
        if guard_type not in self.guard_type_to_vars:
            self.guard_type_to_vars[guard_type] = set()
        self.guard_type_to_vars[guard_type].add(variable)
    
    def has_guard_for_variable(self, guard_type: str, variable: str) -> bool:
        """
        Check if any guard of the given type is established for this variable.
        
        This is the interprocedural query interface.
        """
        vars_with_guard = self.guard_type_to_vars.get(guard_type, set())
        return variable in vars_with_guard
    
    def has_guard_for_variable_or_alias(self, guard_type: str, variable: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a guard is established for this variable or any of its aliases.
        
        This enables guard propagation through value flow:
        - If x is guarded and y = x, then y is also guarded
        - Returns (True, alias_var) if guarded through an alias
        - Returns (True, None) if directly guarded
        - Returns (False, None) if not guarded
        """
        vars_with_guard = self.guard_type_to_vars.get(guard_type, set())
        
        # Check direct guard
        if variable in vars_with_guard:
            return (True, None)
        
        # Check through aliases
        aliases = self.value_aliases.get(variable, set())
        for alias in aliases:
            if alias in vars_with_guard:
                return (True, alias)
        
        # Check reverse direction: does any guarded variable alias to this one?
        for guarded_var in vars_with_guard:
            if variable in self.value_aliases.get(guarded_var, set()):
                return (True, guarded_var)
        
        return (False, None)
    
    def get_all_guarded_variables(self, guard_type: str) -> Set[str]:
        """Get all variables that have the given guard type established."""
        return self.guard_type_to_vars.get(guard_type, set()).copy()
    
    def add_value_alias(self, target: str, source: str) -> None:
        """
        Record that target variable holds the same value as source variable.
        
        This creates a bidirectional alias relationship for guard propagation.
        """
        if target not in self.value_aliases:
            self.value_aliases[target] = set()
        self.value_aliases[target].add(source)
        
        # Also record reverse direction
        if source not in self.value_aliases:
            self.value_aliases[source] = set()
        self.value_aliases[source].add(target)
    
    def get_all_aliases(self, variable: str) -> Set[str]:
        """
        Get all variables that may hold the same value as this variable.
        
        Returns the transitive closure of aliases.
        """
        result = set()
        visited = set()
        worklist = [variable]
        
        while worklist:
            var = worklist.pop()
            if var in visited:
                continue
            visited.add(var)
            
            aliases = self.value_aliases.get(var, set())
            for alias in aliases:
                if alias not in visited:
                    result.add(alias)
                    worklist.append(alias)
        
        return result
    
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
    
    def record_bug_instance(self, bug_type: str, is_guarded: bool) -> None:
        """
        Record a bug instance with its guard status.
        
        ITERATION 702: Track per-instance guard counts for accurate FP measurement.
        """
        if bug_type not in self.guard_counts:
            self.guard_counts[bug_type] = (0, 0)
        
        guarded, unguarded = self.guard_counts[bug_type]
        if is_guarded:
            self.guard_counts[bug_type] = (guarded + 1, unguarded)
            self.guarded_bugs.add(bug_type)
        else:
            self.guard_counts[bug_type] = (guarded, unguarded + 1)
            self.may_trigger.add(bug_type)
    
    def get_fp_rate(self, bug_type: str) -> float:
        """
        Get the false positive rate for a bug type.
        
        FP rate = guarded / (guarded + unguarded)
        A higher rate means more instances are false positives.
        """
        if bug_type not in self.guard_counts:
            return 0.0
        guarded, unguarded = self.guard_counts[bug_type]
        total = guarded + unguarded
        return guarded / total if total > 0 else 0.0
    
    def get_guarded_count(self, bug_type: str) -> int:
        """Get count of guarded (FP) instances for a bug type."""
        if bug_type not in self.guard_counts:
            return 0
        return self.guard_counts[bug_type][0]
    
    def get_unguarded_count(self, bug_type: str) -> int:
        """Get count of unguarded (potential TP) instances for a bug type."""
        if bug_type not in self.guard_counts:
            return 0
        return self.guard_counts[bug_type][1]
    
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
# BYTECODE CRASH SUMMARY ANALYZER (Primary Analysis Path)
# ============================================================================
# Note: AST-based CrashSummaryAnalyzer removed - bytecode analysis is more
# precise and integrates better with verification engines.

# Supporting data structures for bytecode analysis
@dataclass
class BytecodeLocation:
    """Location of a bytecode instruction."""
    opname: str
    offset: int
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
    AST visitor that computes crash summary for a single function.
    
    Analyzes:
    - What operations may crash (division, subscript, attribute access)
    - What exceptions are raised or may propagate
    - Nullability flow from params to operations
    
    ITERATION 611: Adds guard tracking for FP reduction.
    From barrier-certificate-theory.tex: guards from control flow (if x is not None)
    make subsequent operations safe. We track these to avoid false positives.
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
        
        # ITERATION 611: Guard tracking for FP reduction
        self.guards = GuardTracker()
    
    def analyze(self, func_node: ast.FunctionDef) -> CrashSummary:
        """Analyze function and return crash summary."""
        # ITERATION 610: Initialize param nullability from type annotations
        self._init_param_nullability_from_annotations(func_node)
        
        # ITERATION 611: 'self' and 'cls' are guaranteed non-None
        if self.parameters and self.parameters[0] == 'self':
            self.guards.nonnull_vars.add('self')
            self.summary.param_nullability[0] = Nullability.NOT_NONE
        if self.parameters and self.parameters[0] == 'cls':
            self.guards.nonnull_vars.add('cls')
            self.summary.param_nullability[0] = Nullability.NOT_NONE
        
        # NOTE: Removed NEVER_NONE_NAMES heuristic
        # Only 'self' and 'cls' are semantically guaranteed non-None by Python
        # Other guarantees should come from type annotations or DSE analysis
        
        # Only visit the function body, not annotations/decorators
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
            # ITERATION 611: Check guards first
            if node.id in self.guards.nonnull_vars:
                return Nullability.NOT_NONE
            # Check if it's a param we know about
            if node.id in self.param_indices:
                idx = self.param_indices[node.id]
                return self.summary.param_nullability.get(idx, Nullability.TOP)
        return Nullability.TOP
    
    def _get_name_str(self, node: ast.AST) -> str:
        """Get string representation of a name or attribute chain."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_name_str(node.value)
            return f'{base}.{node.attr}' if base else node.attr
        elif isinstance(node, ast.Subscript):
            return self._get_name_str(node.value)
        elif isinstance(node, ast.Call):
            return self._get_name_str(node.func)
        return ''
    
    def _is_path_division(self, left: ast.AST) -> bool:
        """
        Check if division is Path.__truediv__ (not numeric).
        
        Path / "file" uses the / operator but is path concatenation, not division.
        
        DSE-based approach: Use type inference from Z3 symbolic values to determine
        if the operand is a Path type. The SymbolicVM tracks types precisely.
        
        For AST-level analysis, we use type annotations when available.
        """
        # Use type annotations if available
        if isinstance(left, ast.Name):
            # Check if we have type info from annotations
            if hasattr(self, 'type_annotations') and left.id in self.type_annotations:
                type_str = self.type_annotations.get(left.id, '')
                if 'Path' in type_str or 'path' in type_str.lower():
                    return True
        # For attribute access like self.path, check type annotations on class
        if isinstance(left, ast.Attribute):
            if hasattr(self, 'type_annotations'):
                attr_type = self.type_annotations.get(f'{self._get_name_str(left.value)}.{left.attr}', '')
                if 'Path' in attr_type:
                    return True
        # Conservative: cannot determine without DSE type inference
        return False
    
    def _body_terminates(self, body: List[ast.AST]) -> bool:
        """
        Check if a block always terminates (raise, return, continue, break).
        
        ITERATION 611: For early-return patterns like:
            if x is None:
                raise ValueError(...)
            # After here, x is definitely not None
        """
        if not body:
            return False
        last = body[-1]
        # Direct terminators
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        # If with terminating branches
        if isinstance(last, ast.If):
            if_terminates = self._body_terminates(last.body)
            else_terminates = self._body_terminates(last.orelse) if last.orelse else False
            return if_terminates and else_terminates
        return False
    
    def _extract_inverted_guards(self, test: ast.AST) -> None:
        """
        Extract guards from the OPPOSITE of a test condition.
        
        Used after 'if x is None: raise' - after the if, x is NOT None.
        """
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
            # (handled by UnaryOp below)
        
        # if not x: raise -> x is truthy after
        elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            if isinstance(test.operand, ast.Name):
                self.guards.nonnull_vars.add(test.operand.id)
                self.guards.nonempty_vars.add(test.operand.id)
                self.guards.nonzero_vars.add(test.operand.id)
    
    def visit_If(self, node: ast.If) -> None:
        """
        ITERATION 611: Extract guards from if conditions.
        
        Track guards like 'if x is not None:' to reduce FPs in the body.
        Also handle early-return patterns: 'if x is None: raise'
        """
        old_guards = self.guards.copy()
        
        # Check for early-return pattern: if condition: <terminate>
        # After this pattern, the INVERSE of the condition holds
        if self._body_terminates(node.body) and not node.orelse:
            # After the if, the condition is FALSE
            self._extract_inverted_guards(node.test)
            # Still need to visit the body for its own analysis
            for stmt in node.body:
                self.visit(stmt)
            # Don't restore guards - the inverted guards persist
            return
        
        # Normal case: extract guards from the test condition
        self._extract_guards_from_test(node.test)
        
        # Visit body with updated guards
        for stmt in node.body:
            self.visit(stmt)
        
        # Restore guards for else branch (opposite knowledge)
        self.guards = old_guards
        for stmt in node.orelse:
            self.visit(stmt)
    
    def _extract_guards_from_test(self, test: ast.AST) -> None:
        """Extract guard facts from an if condition."""
        # if x is not None:
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            if isinstance(test.ops[0], ast.IsNot):
                if isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None:
                    if isinstance(test.left, ast.Name):
                        self.guards.nonnull_vars.add(test.left.id)
            
            # if x != 0: or if x > 0:
            elif isinstance(test.ops[0], (ast.NotEq, ast.Gt)):
                if isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == 0:
                    if isinstance(test.left, ast.Name):
                        self.guards.nonzero_vars.add(test.left.id)
            
            # if len(x) > 0:
            elif isinstance(test.ops[0], ast.Gt):
                if isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == 0:
                    if isinstance(test.left, ast.Call):
                        if isinstance(test.left.func, ast.Name) and test.left.func.id == 'len':
                            if test.left.args and isinstance(test.left.args[0], ast.Name):
                                self.guards.nonempty_vars.add(test.left.args[0].id)
        
        # if x: (truthiness implies non-None and non-empty/zero)
        elif isinstance(test, ast.Name):
            self.guards.nonnull_vars.add(test.id)
            self.guards.nonempty_vars.add(test.id)
            self.guards.nonzero_vars.add(test.id)
        
        # if x and y: (both must be truthy)
        elif isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            for value in test.values:
                self._extract_guards_from_test(value)
    
    def visit_For(self, node: ast.For) -> None:
        """
        ITERATION 611: Track loop iteration for safe indexing.
        
        for i, x in enumerate(lst): lst[i] is always safe
        for i in range(len(lst)): lst[i] is always safe
        """
        old_guards = self.guards.copy()
        
        # for x in container:
        if isinstance(node.iter, ast.Name):
            container = node.iter.id
            if isinstance(node.target, ast.Name):
                self.guards.loop_vars[node.target.id] = container
        
        # for i, x in enumerate(container):
        elif isinstance(node.iter, ast.Call):
            if isinstance(node.iter.func, ast.Name):
                if node.iter.func.id == 'enumerate':
                    if node.iter.args and isinstance(node.iter.args[0], ast.Name):
                        container = node.iter.args[0].id
                        if isinstance(node.target, ast.Tuple) and len(node.target.elts) >= 2:
                            if isinstance(node.target.elts[0], ast.Name):
                                self.guards.loop_vars[node.target.elts[0].id] = container
                
                # for i in range(len(x)):
                elif node.iter.func.id == 'range':
                    if node.iter.args:
                        arg = node.iter.args[0]
                        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                            if arg.func.id == 'len' and arg.args:
                                if isinstance(arg.args[0], ast.Name):
                                    container = arg.args[0].id
                                    if isinstance(node.target, ast.Name):
                                        self.guards.loop_vars[node.target.id] = container
        
        # Visit loop body
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        
        self.guards = old_guards
    
    # NOTE: REMOVED ad-hoc _is_safe_divisor_pattern that matched names like "count", "size"
    # This was rejected as non-principled. Proper FP reduction uses:
    # 1. SymbolicVM DSE with Z3 reachability checking
    # 2. GuardDataflowAnalysis for guard propagation through CFG
    # 3. Barrier certificate synthesis for safety proofs
    
    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Check for division by zero risk with FP reduction."""
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            # ITERATION 611: Skip Path division (FP)
            if self._is_path_division(node.left):
                self.generic_visit(node)
                return
            
            # ITERATION 611: Skip if divisor is guarded non-zero
            if isinstance(node.right, ast.Name):
                if node.right.id in self.guards.nonzero_vars:
                    self.generic_visit(node)
                    return
            
            # ITERATION 611: Skip constant non-zero divisors
            if isinstance(node.right, ast.Constant):
                if isinstance(node.right.value, (int, float)) and node.right.value != 0:
                    self.generic_visit(node)
                    return
            
            # ITERATION 611: Skip division by len(x) where x is non-empty
            if isinstance(node.right, ast.Call):
                if isinstance(node.right.func, ast.Name) and node.right.func.id == 'len':
                    if node.right.args and isinstance(node.right.args[0], ast.Name):
                        if node.right.args[0].id in self.guards.nonempty_vars:
                            self.generic_visit(node)
                            return
            
            # NOTE: REMOVED call to _is_safe_divisor_pattern (ad-hoc name matching)
            # Proper FP reduction uses DSE with Z3 reachability checking
            
            # Not filtered - this is a potential bug
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
            # ITERATION 611: Check guards
            if node.id in self.guards.nonzero_vars:
                return False
            # Parameter or variable - could be zero
            return True
        return True  # Conservative
    
    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Check for bounds/key error risk with FP reduction."""
        container_sources = self._get_param_sources(node.value)
        index_sources = self._get_param_sources(node.slice)
        
        # Only flag BOUNDS for Load context (reading)
        if not isinstance(node.ctx, (ast.Load, ast.Del)):
            self.generic_visit(node)
            return
        
        # ITERATION 611: Check for safe loop indexing patterns
        container_name = self._get_name_str(node.value)
        
        # Check if index is from iteration over the same container
        if isinstance(node.slice, ast.Name):
            idx_name = node.slice.id
            if self.guards.is_safe_loop_index(idx_name, container_name):
                # for i in range(len(x)): x[i] is safe
                self.generic_visit(node)
                return
        
        # ITERATION 611: len(x) - 1 is safe if x is non-empty
        if isinstance(node.slice, ast.BinOp) and isinstance(node.slice.op, ast.Sub):
            if isinstance(node.slice.left, ast.Call):
                call = node.slice.left
                if isinstance(call.func, ast.Name) and call.func.id == 'len':
                    if isinstance(node.slice.right, ast.Constant):
                        if isinstance(node.slice.right.value, int) and node.slice.right.value >= 1:
                            if call.args and isinstance(call.args[0], ast.Name):
                                if call.args[0].id in self.guards.nonempty_vars:
                                    self.generic_visit(node)
                                    return
        
        # ITERATION 611: Constant indices 0, -1 safe if container is non-empty
        if isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, int) and node.slice.value in (0, -1):
                if container_name in self.guards.nonempty_vars:
                    self.generic_visit(node)
                    return
        
        # Not filtered - this is a potential BOUNDS issue
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
        """Check for None dereference risk with FP reduction."""
        # Check if object is guarded as non-None via CFG dataflow analysis
        if isinstance(node.value, ast.Name):
            if node.value.id in self.guards.nonnull_vars:
                self.generic_visit(node)
                return
            # Check type annotations for non-nullable types
            if hasattr(self, 'type_annotations'):
                type_str = self.type_annotations.get(node.value.id, '')
                # Non-Optional types are not None
                if type_str and 'Optional' not in type_str and 'None' not in type_str:
                    self.generic_visit(node)
                    return
            # 'self' and 'cls' are guaranteed non-None by Python semantics
            if node.value.id in ('self', 'cls'):
                self.generic_visit(node)
                return
        
        obj_sources = self._get_param_sources(node.value)
        obj_null = self._get_nullability(node.value)
        
        # Attribute access on None causes NULL_PTR
        # DSE-based approach: Use Z3 to check if None is reachable
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

    """
    Bytecode-level crash summary analyzer.
    
    Operates on types.CodeType objects directly, using:
    - CFG from cfg.control_flow.build_cfg
    - Guard/type/bounds analysis from cfg.dataflow.run_intraprocedural_analysis
    - Integrates with unsafe.registry.UNSAFE_PREDICATES
    
    This is the canonical analysis matching the "bytecode-as-abstract-machine"
    semantics described in barrier-certificate-theory.tex.
    
    This is the PRIMARY and ONLY crash summary analyzer. AST-based analysis
    was removed as bytecode provides better precision and verification integration.
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
        
        # Exception handler analysis for barrier detection
        self.exception_analyzer: ExceptionCatchAnalyzer = ExceptionCatchAnalyzer(self.cfg)
        
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

        # SOTA papers #4-5 (SOSTOOLS + Putinar): compact-domain SAFE proofs.
        # Used to suppress unsound interprocedural preconditions like "param != 0"
        # when a division site is provably unreachable (e.g., inside `while 1 <= x <= 5`).
        self._compact_proven_safe_sites: Dict[str, Set[int]] = {}
        if any(
            ins.opname == "BINARY_OP" and isinstance(ins.arg, int) and ins.arg in DIVISION_BINARY_OPS
            for ins in self.instructions
        ):
            try:
                from ..barriers.sos_toolbox import prove_guarded_hazards_compact

                for proof in prove_guarded_hazards_compact(code):
                    self._compact_proven_safe_sites.setdefault(proof.bug_type, set()).add(proof.site_offset)
            except Exception:
                # If proofs fail for any reason, fall back to conservative reporting.
                self._compact_proven_safe_sites = {}
        
        # Build summary
        self.summary = CrashSummary(
            function_name=func_name,
            qualified_name=qualified_name,
            parameter_count=self.param_count,
        )
        
        # BYTECODE STORAGE: Store instructions for barrier-theoretic stdlib detection
        # This enables Papers #9-12 (ICE), #13-16 (IC3), #17-20 (CHC) to analyze
        # stdlib usage patterns (len(), max(), range()) and synthesize barriers
        self.summary.bytecode_instructions = self.instructions
        
        # Track locations of potential crashes
        self.crash_locations: List[Tuple[str, BytecodeLocation]] = []
        
        # Return nullability tracking
        self._return_nullabilities: List[Nullability] = []
        
        # ITERATION 610: Track locals known to be non-None
        # Maps local_idx -> True if known non-None (from BUILD_MAP, BUILD_LIST, etc.)
        self._nonnull_locals: Dict[int, bool] = {}
    
    def _is_caught_exception(self, offset: int, bug_type: str) -> bool:
        """
        Check if exception for this bug type is caught at this offset.
        
        If the exception is caught, the bug is "handled" and should not be reported
        as a bug (though it may still be logged as a guarded case).
        
        This implements the exception barrier from barrier-certificate-theory.tex:
        WillCatchAt(pc, exc) = True implies the exception is handled locally.
        """
        exception_types = EXCEPTION_BARRIER_MAP.get(bug_type, [])
        for exc_type in exception_types:
            if self.exception_analyzer.will_catch_at(offset, exc_type):
                return True
        return False
    
    def analyze(self) -> CrashSummary:
        """
        Analyze bytecode and build crash summary.
        
        Walks through all basic blocks, checking each instruction for:
        - Division by potential zero
        - Subscript access (bounds risk)
        - Attribute access (null dereference risk)
        - Calls to potentially dangerous functions
        - Raises
        
        INTERPROCEDURAL EXTENSION: Also computes return guarantees and
        parameter validation facts for cross-function guard propagation.
        
        AUTOMATIC GUARD PROPAGATION: Uses GuardAnalyzer to collect all
        intraprocedural guard facts, which are then stored in the summary
        for interprocedural use. Any guard pattern added to GuardAnalyzer
        will automatically be available interprocedurally.
        
        DSE INTEGRATION: Uses full DSE path condition tracking to identify
        bugs that are provably unreachable (FPs) through:
        - Path condition tracking with Z3 constraints
        - Infeasible path pruning (SAT check)
        - Richer value flow through function returns and container ops
        - Path-sensitive guard analysis
        - Type-based filtering (self is never None)
        """
        # ITERATION 610: First pass - identify non-null locals
        # Scan for BUILD_MAP/BUILD_LIST followed by STORE_FAST
        self._identify_nonnull_locals()
        
        # Compute parameter flow through the function
        flows = self._compute_parameter_flows()
        
        # AUTOMATIC GUARD PROPAGATION: Run GuardAnalyzer and store all guard facts
        # This is the key refactor - any guard pattern in control_flow.py
        # automatically becomes available for interprocedural analysis
        self._collect_intraprocedural_guards()
        
        # VALUE FLOW TRACKING: Compute variable aliases for guard propagation
        # This enables guards to apply through assignments (y = x => guard(x) => guard(y))
        self._compute_value_aliases()
        
        # DSE INTEGRATION: Run value flow analyzer for richer guard propagation
        self._run_dse_value_flow_analysis()
        
        # PATH-SENSITIVE ANALYSIS: Run path-sensitive guard analyzer
        self._run_path_sensitive_analysis()
        
        # Analyze each block
        for block_id, block in self.cfg.blocks.items():
            for instr in block.instructions:
                self._analyze_instruction(instr, block, flows)
        
        # DSE POST-PROCESSING: Use DSE to filter out unreachable bugs
        self._filter_bugs_with_dse()
        
        # Compute final return nullability
        if self._return_nullabilities:
            result = Nullability.BOTTOM
            for n in self._return_nullabilities:
                result = result.join(n)
            self.summary.return_nullability = result
        
        # INTERPROCEDURAL: Compute return guarantees based on return nullability
        if self.summary.return_nullability == Nullability.NOT_NONE:
            self.summary.return_guarantees.add('nonnull')
        
        # Compute interprocedural return and param guarantees
        self._compute_interprocedural_guarantees()
        
        self.summary.analyzed = True
        return self.summary
    
    def _run_dse_value_flow_analysis(self) -> None:
        """
        Run DSE-based value flow analysis for richer guard propagation.
        
        This tracks values through:
        - Function returns (if f() returns nonnull, result is nonnull)
        - Container operations (track values through list/dict ops)
        - Attribute access chains
        """
        try:
            from ..dse.value_flow import ValueFlowAnalyzer, FunctionReturnSemantics
            
            analyzer = ValueFlowAnalyzer(self.code)
            flow_graph = analyzer.analyze()
            
            # Get nonnull variables from value flow analysis
            nonnull_vars = analyzer.get_nonnull_variables()
            
            # Add nonnull facts to the summary
            for var in nonnull_vars:
                self.summary.add_guard_fact('nonnull', var, None, block_id=0)
            
            # Store flow graph for later use
            self._value_flow_graph = flow_graph
            
        except ImportError:
            # DSE module not available, skip
            self._value_flow_graph = None
    
    def _run_path_sensitive_analysis(self) -> None:
        """
        Run path-sensitive guard analysis.
        
        This tracks different guard states on different CFG paths,
        enabling more precise FP reduction than path-insensitive analysis.
        """
        try:
            from ..dse.value_flow import PathSensitiveGuardAnalyzer
            
            analyzer = PathSensitiveGuardAnalyzer(self.code, max_paths=50)
            self._path_states = analyzer.analyze()
            self._path_sensitive_analyzer = analyzer
            
        except ImportError:
            # DSE module not available, skip
            self._path_states = {}
            self._path_sensitive_analyzer = None
    
    def _filter_bugs_with_dse(self) -> None:
        """
        Use full DSE to filter out bugs that are provably unreachable.
        
        For each potential bug, we check:
        SAT(path_condition ∧ bug_condition) = UNSAT → bug is FP
        
        This provides stronger FP reduction than simple guard analysis.
        """
        try:
            from ..dse.path_condition import DSEExecutor
            
            # Run DSE path exploration
            executor = DSEExecutor(
                self.code,
                max_paths=100,
                max_depth=50,
                solver_timeout_ms=1000,
            )
            executor.analyze()
            
            # Check each crash location
            filtered_crashes = []
            for bug_type, location in self.crash_locations:
                # Get the variable involved in the bug
                bug_var = self._get_bug_variable(bug_type, location)
                
                # Check if bug is reachable using DSE
                is_reachable, _ = executor.check_bug_reachable(
                    bug_type, bug_var, location.offset
                )
                
                if is_reachable:
                    # Bug may be reachable - keep it
                    filtered_crashes.append((bug_type, location))
                else:
                    # Bug is provably unreachable (FP) - upgrade to guarded
                    self.summary.record_bug_instance(bug_type, is_guarded=True)
                    # Don't add to filtered list
            
            self.crash_locations = filtered_crashes
            
        except (ImportError, Exception) as e:
            # DSE not available or failed, keep original crashes
            pass
    
    def _get_bug_variable(self, bug_type: str, location: 'BytecodeLocation') -> str:
        """Extract the variable involved in a bug from its location."""
        # Get instruction at location
        idx = self._instr_index_by_offset.get(location.offset)
        if idx is None:
            return f"var_at_{location.offset}"
        
        instr = self.instructions[idx]
        
        if bug_type == 'DIV_ZERO':
            # Divisor is TOS, look back for the load
            if idx > 0:
                prev = self.instructions[idx - 1]
                if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                    return prev.argval or f"local_{prev.arg}"
        
        elif bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
            # Object is TOS
            if idx > 0:
                prev = self.instructions[idx - 1]
                if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                    return prev.argval or f"local_{prev.arg}"
        
        elif bug_type in ('BOUNDS', 'INDEX_ERROR'):
            # Container[index] - need both
            container = self._get_container_name_at(location.offset)
            index = self._get_constant_index_at(location.offset)
            if container and index is not None:
                return f"{container}[{index}]"
            elif container:
                return f"{container}[?]"
        
        return f"var_at_{location.offset}"
    
    def _compute_value_aliases(self) -> None:
        """
        Compute value aliasing between local variables.
        
        This tracks which variables hold the same value, enabling guard
        propagation through assignments:
        
            if x is not None:  # guard established for x
                y = x          # y now aliases x
                z = y          # z aliases y (and transitively x)
                z.attr         # bug on z, but guarded through alias chain
        
        The analysis is a simplified reaching definitions that tracks direct
        assignments between local variables (LOAD_FAST -> STORE_FAST patterns).
        """
        # Track LOAD_FAST -> STORE_FAST patterns across all blocks
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'STORE_FAST' and i >= 1:
                    target_var = instr.argval
                    if not target_var:
                        continue
                    
                    # Check if previous instruction is LOAD_FAST (direct assignment y = x)
                    prev = block.instructions[i - 1]
                    if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                        source_var = prev.argval
                        if source_var and source_var != target_var:
                            # Direct assignment: target = source
                            self.summary.add_value_alias(target_var, source_var)
                    
                    # Also check for COPY before STORE (walrus operator pattern)
                    # CALL -> COPY -> STORE_FAST creates alias from call result
                    elif prev.opname == 'COPY' and i >= 2:
                        # The value being copied might come from a guarded call
                        # We track this as the target being an alias of itself
                        # (used for walrus operator patterns)
                        pass
    
    def _collect_intraprocedural_guards(self) -> None:
        """
        Collect all guard facts from the intraprocedural GuardAnalyzer.
        
        This is the bridge between intraprocedural and interprocedural analysis.
        Every guard pattern detected by GuardAnalyzer (in control_flow.py) is
        automatically stored in the CrashSummary for interprocedural use.
        
        Guard types collected:
        - nonnull: variable is not None
        - div: variable is non-zero (safe for division)
        - bounds: container[index] is in bounds
        - nonempty: container has len >= 1
        - exact_length: container has exactly n elements
        - range_len_loop: index from range(len(container))
        - enumerate_loop: index from enumerate(container)
        - loop_body_nonempty: container nonempty during iteration
        - key_in: key is in container
        - hasattr: object has attribute
        - nonnegative: value >= 0
        - type: isinstance check passed
        - exception_caught: in exception handler
        - callable: callable check passed
        
        All these automatically propagate to interprocedural analysis.
        """
        from ..cfg.control_flow import GuardAnalyzer
        
        guard_analyzer = GuardAnalyzer(self.cfg)
        block_guards = guard_analyzer.analyze()
        
        # Store each guard fact in the summary
        for block_id, guards in block_guards.items():
            for guard in guards:
                self.summary.add_guard_fact(
                    guard_type=guard.guard_type,
                    variable=guard.variable,
                    extra=guard.extra,
                    block_id=block_id,
                )
                
                # Also update validated_params if this is a parameter
                param_names = list(self.code.co_varnames[:self.param_count])
                if guard.variable in param_names:
                    param_idx = param_names.index(guard.variable)
                    if param_idx not in self.summary.validated_params:
                        self.summary.validated_params[param_idx] = set()
                    self.summary.validated_params[param_idx].add(guard.guard_type)
                
                # Update return_guarantees based on guard types for return values
                # If a local variable has a guard and flows to return, propagate it
                if guard.guard_type == 'nonnull':
                    # Track that this variable is known nonnull
                    pass  # Already tracked in guard_type_to_vars
    
    def _compute_interprocedural_guarantees(self) -> None:
        """
        Compute interprocedural guard guarantees for this function.
        
        Analyzes:
        1. Return value guarantees (nonnull, nonzero, etc.)
        2. Parameter validation (which params are checked before use)
        
        These facts enable FP reduction at call sites.
        """
        # Analyze return statements for guarantees
        self._analyze_return_guarantees()
        
        # Analyze parameter validation patterns
        self._analyze_parameter_validation()
    
    def _analyze_return_guarantees(self) -> None:
        """
        Analyze all return paths to determine return value guarantees.
        
        A guarantee holds if ALL return paths satisfy it.
        """
        return_nonnull_count = 0
        return_total_count = 0
        
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'RETURN_VALUE':
                    return_total_count += 1
                    if self._is_return_nonnull(block, i):
                        return_nonnull_count += 1
        
        # If all returns are nonnull, function guarantees nonnull
        if return_total_count > 0 and return_nonnull_count == return_total_count:
            self.summary.return_guarantees.add('nonnull')
    
    def _is_return_nonnull(self, block: 'BasicBlock', return_idx: int) -> bool:
        """Check if a specific return is guaranteed nonnull."""
        if return_idx < 1:
            return False
        
        # Check previous instruction to see what's being returned
        prev = block.instructions[return_idx - 1] if return_idx > 0 else None
        if not prev:
            return False
        
        # Direct constant return
        if prev.opname == 'LOAD_CONST':
            const_val = prev.argval
            return const_val is not None
        
        # Return from BUILD_* (always nonnull)
        if prev.opname.startswith('BUILD_'):
            return True
        
        # Return from CALL to constructor/builtin
        if prev.opname in ('CALL', 'CALL_FUNCTION'):
            # Look back for function name
            for j in range(return_idx - 2, max(-1, return_idx - 6), -1):
                call_instr = block.instructions[j]
                if call_instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                    func_name = call_instr.argval
                    if self._is_nonnull_returning_function(func_name):
                        return True
                    break
                elif call_instr.opname == 'LOAD_ATTR':
                    attr_name = call_instr.argval
                    if self._is_nonnull_returning_method(attr_name):
                        return True
                    break
        
        # Return a local variable with nonnull guard
        if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
            local_idx = prev.arg
            if local_idx in self._nonnull_locals:
                return True
            # Check if guard is established
            guard_state = self.intraproc.guard_state_at(prev.offset) if hasattr(self.intraproc, 'guard_state_at') else None
            if guard_state and guard_state.has_nonnull(prev.argval):
                return True
        
        return False
    
    def _is_nonnull_returning_function(self, func_name: str) -> bool:
        """Check if a function always returns nonnull."""
        NONNULL_FUNCTIONS = {
            'list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool',
            'bytes', 'bytearray', 'frozenset', 'object', 'range', 'slice', 'type',
            'len', 'abs', 'repr', 'hash', 'id', 'chr', 'ord', 'bin', 'hex', 'oct',
            'sorted', 'reversed', 'enumerate', 'zip', 'map', 'filter',
        }
        if func_name in NONNULL_FUNCTIONS:
            return True
        # Capitalized names are likely constructors
        if isinstance(func_name, str) and func_name and func_name[0].isupper():
            return True
        return False
    
    def _is_nonnull_returning_method(self, method_name: str) -> bool:
        """Check if a method always returns nonnull."""
        NONNULL_METHODS = {
            'strip', 'lstrip', 'rstrip', 'split', 'rsplit', 'splitlines',
            'lower', 'upper', 'title', 'capitalize', 'swapcase', 'casefold',
            'replace', 'encode', 'format', 'join', 'center', 'ljust', 'rjust',
            'keys', 'values', 'items', 'copy',
        }
        return method_name in NONNULL_METHODS
    
    def _analyze_parameter_validation(self) -> None:
        """
        Analyze which parameters are validated by this function.
        
        Looks for patterns like:
        - if param is None: raise/return
        - if not param: raise/return
        - assert param is not None
        
        If a parameter is validated, callers can trust that if the function
        returns normally, the parameter was valid.
        """
        # Get guard analysis results
        guard_analyzer = GuardAnalyzer(self.cfg)
        block_guards = guard_analyzer.analyze()
        
        # Check which parameters have guards established
        param_names = list(self.code.co_varnames[:self.param_count])
        
        for param_idx, param_name in enumerate(param_names):
            validated_guards: Set[str] = set()
            
            for block_id, guards in block_guards.items():
                for guard in guards:
                    if guard.variable == param_name:
                        if guard.guard_type == 'nonnull':
                            validated_guards.add('nonnull')
                        elif guard.guard_type == 'div':
                            validated_guards.add('nonzero')
                        elif guard.guard_type == 'nonempty':
                            validated_guards.add('nonempty')
                        elif guard.guard_type == 'type':
                            validated_guards.add(f'type:{guard.extra}')
            
            if validated_guards:
                self.summary.validated_params[param_idx] = validated_guards
    
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
    
    def _push_stack(self, flow: ParameterFlow, value: Set[int]) -> None:
        """Push a value onto the stack, shifting existing values down."""
        # Shift all existing stack positions down (TOS->TOS1, TOS1->TOS2, etc.)
        new_stack = {}
        for pos, val in flow.stack_flows.items():
            new_stack[pos + 1] = val
        new_stack[0] = value  # New TOS
        flow.stack_flows = new_stack
    
    def _pop_stack(self, flow: ParameterFlow) -> Set[int]:
        """Pop TOS and shift stack up."""
        result = flow.stack_flows.get(0, set())
        new_stack = {}
        for pos, val in flow.stack_flows.items():
            if pos > 0:
                new_stack[pos - 1] = val
        flow.stack_flows = new_stack
        return result
    
    def _update_flow_for_instruction(self, instr: dis.Instruction, flow: ParameterFlow) -> None:
        """Update parameter flow for a single instruction with proper stack semantics."""
        opname = instr.opname
        
        if opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
            # Load local to stack - pushes one value
            local_idx = instr.arg
            value = flow.local_flows.get(local_idx, set()).copy()
            self._push_stack(flow, value)

        elif opname == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
            # Python 3.14 specialized opcode: pushes two locals.
            # Pushes names[0] first, then names[1] (so names[1] ends up as TOS)
            names = instr.argval if isinstance(instr.argval, tuple) else None
            if names and len(names) == 2:
                try:
                    local_idx_0 = list(self.code.co_varnames).index(names[0])
                except ValueError:
                    local_idx_0 = None
                try:
                    local_idx_1 = list(self.code.co_varnames).index(names[1])
                except ValueError:
                    local_idx_1 = None
                
                # Push first value (becomes TOS1 after second push)
                val_0 = flow.local_flows.get(local_idx_0, set()).copy() if local_idx_0 is not None else set()
                self._push_stack(flow, val_0)
                
                # Push second value (becomes TOS)
                val_1 = flow.local_flows.get(local_idx_1, set()).copy() if local_idx_1 is not None else set()
                self._push_stack(flow, val_1)
        
        elif opname == 'STORE_FAST':
            # Pop from stack and store to local
            local_idx = instr.arg
            value = self._pop_stack(flow)
            flow.local_flows[local_idx] = value
        
        elif opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
            # Load constant - pushes non-param value
            self._push_stack(flow, set())
        
        elif opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
            # Load global/name - pushes non-param value
            self._push_stack(flow, set())
        
        elif opname == 'BINARY_OP':
            # Pops TOS and TOS1, pushes result
            # For subscript (arg=26): TOS1[TOS] - container is TOS1, index is TOS
            right = self._pop_stack(flow)  # TOS (index for subscript)
            left = self._pop_stack(flow)   # TOS1 (container for subscript)
            # For flow tracking, the result carries both sources
            self._push_stack(flow, left | right)
        
        elif opname == 'CALL':
            # Simplified: pops args and callable, pushes result
            # For now, just clear stack flows (conservative)
            flow.stack_flows = {0: set()}
        
        elif opname in ('POP_TOP', 'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
                        'POP_JUMP_IF_NONE', 'POP_JUMP_IF_NOT_NONE'):
            # Pop one value
            self._pop_stack(flow)
        
        elif opname in ('RETURN_VALUE', 'RETURN_CONST'):
            # Clears stack
            flow.stack_flows = {}
        
        elif opname in ('COMPARE_OP', 'CONTAINS_OP', 'IS_OP'):
            # Binary comparison: pops 2, pushes 1
            self._pop_stack(flow)
            self._pop_stack(flow)
            self._push_stack(flow, set())
    
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
        # Note: Slice operations never raise IndexError, only scalar subscripts do
        # Also filter out safe indexing patterns like split()[0]
        # Also filter out dict access with string keys (raises KeyError, not IndexError)
        elif opname == 'BINARY_OP' and instr.arg in SUBSCRIPT_BINARY_OPS:
            # Check if this is a slice operation (LOAD_CONST slice(...))
            if (not self._is_slice_subscript(location.offset) and 
                not self._is_safe_indexing(location.offset) and
                not self._is_string_key_subscript(location.offset)):
                self._check_subscript(location, flow, guards)
        
        # Check for subscript access (older Python versions)
        elif opname in SUBSCRIPT_OPCODES:
            # Check if this is a slice operation or safe indexing
            if (not self._is_slice_subscript(location.offset) and 
                not self._is_safe_indexing(location.offset) and
                not self._is_string_key_subscript(location.offset)):
                self._check_subscript(location, flow, guards)
        
        # Note: BINARY_SLICE never raises IndexError - slices return empty for out-of-range
        # So we don't check BINARY_SLICE for BOUNDS
        
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
        if location.offset in self._compact_proven_safe_sites.get("DIV_ZERO", set()):
            return

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
                # Check if RHS is a string (string formatting with %)
                if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, str):
                    return
            
            # Check for Path division pattern (Path / "name")
            # Pattern: LOAD_ATTR parent or Path(...), then LOAD_CONST "string", then /
            if self._is_path_or_string_division_bytecode(idx):
                return
            
            # BYTECODE FP REDUCTION: Check for validation patterns
            # Pattern: if x > 0: ... / x  or  assert x > 0; ... / x
            # Look backward for comparison/assert that validates divisor
            if self._has_divisor_validation_bytecode(idx, divisor_params):
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
        
        # Exception barrier: check if ZeroDivisionError is caught at this site
        if not is_guarded and self._is_caught_exception(location.offset, 'DIV_ZERO'):
            is_guarded = True  # Exception is handled locally
        
        # ITERATION 702: Use record_bug_instance for proper FP tracking
        self.summary.record_bug_instance('DIV_ZERO', is_guarded)
        if not is_guarded:
            self.summary.may_raise.add(ExceptionType.ZERO_DIVISION_ERROR)
            self.crash_locations.append(('DIV_ZERO', location))
    
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
        
        # Check if bounds are guarded using proper Z3-backed dataflow analysis
        is_guarded = False
        
        # First, check if the index is a constant
        # Look at the instruction(s) that loaded the index onto the stack
        constant_index = self._get_constant_index_at(location.offset)
        
        if constant_index is not None:
            # The index is a known constant - check if container bounds include it
            for container_param in container_params:
                container_name = self.code.co_varnames[container_param] if container_param < len(self.code.co_varnames) else f"p{container_param}"
                
                # Use Z3-backed bounds check with constant index
                if guards.has_bounds_safe(container_name, str(constant_index)):
                    is_guarded = True
                    break
            
            # Also check container_params for non-parameter containers
            # by looking at the stack to find the actual container name
            if not is_guarded:
                container_name = self._get_container_name_at(location.offset)
                if container_name:
                    if guards.has_bounds_safe(container_name, str(constant_index)):
                        is_guarded = True
        
        # Check parameter-based bounds guards
        if not is_guarded:
            for idx_param in index_params:
                for container_param in container_params:
                    idx_name = self.code.co_varnames[idx_param] if idx_param < len(self.code.co_varnames) else f"p{idx_param}"
                    container_name = self.code.co_varnames[container_param] if container_param < len(self.code.co_varnames) else f"p{container_param}"
                    
                    # Use the proper Z3-backed bounds guard check
                    if guards.has_bounds_safe(container_name, idx_name):
                        is_guarded = True
                        break
                if is_guarded:
                    break
        
        # Check for range_len_loop guard on container (loop iteration variable is always in bounds)
        # This handles: for i in range(len(arr)): arr[i]
        if not is_guarded:
            for container_param in container_params:
                container_name = self.code.co_varnames[container_param] if container_param < len(self.code.co_varnames) else f"p{container_param}"
                if guards.has_guard("range_len_loop", container_name):
                    is_guarded = True
                    break
        
        # Also check non-parameter container
        if not is_guarded:
            container_name = self._get_container_name_at(location.offset)
            if container_name and guards.has_guard("range_len_loop", container_name):
                is_guarded = True
        
        # Fallback: check numeric bounds analysis
        if not is_guarded:
            for idx_param in index_params:
                var_name = self.code.co_varnames[idx_param] if idx_param < len(self.code.co_varnames) else f"p{idx_param}"
                bounds = self.intraproc.get_bounds(location.offset, var_name)
                if bounds and bounds.lower is not None and bounds.lower >= 0:
                    # Has positive lower bound - partially guarded (non-negative index)
                    is_guarded = True
                    break
        
        # Exception barrier: check if IndexError/KeyError is caught at this site
        if not is_guarded and self._is_caught_exception(location.offset, 'BOUNDS'):
            is_guarded = True  # Exception is handled locally
        
        # ITERATION 702: Use record_bug_instance for proper FP tracking
        self.summary.record_bug_instance('BOUNDS', is_guarded)
        if not is_guarded:
            self.summary.may_raise.add(ExceptionType.INDEX_ERROR)
            self.summary.may_raise.add(ExceptionType.KEY_ERROR)
            self.crash_locations.append(('BOUNDS', location))
    
    def _get_constant_index_at(self, offset: int) -> Optional[int]:
        """
        Get the constant index value for a subscript operation at offset.
        
        Returns the integer constant if the index is a LOAD_CONST or LOAD_SMALL_INT,
        otherwise returns None.
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return None
        
        # Look backward for the index load instruction (skip CACHE/NOP/etc)
        j = idx - 1
        while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP'):
            j -= 1
        
        if j >= 0:
            instr = self.instructions[j]
            if instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
                if isinstance(instr.argval, int):
                    return instr.argval
        
        return None
    
    def _get_container_name_at(self, offset: int) -> Optional[str]:
        """
        Get the container variable name for a subscript operation at offset.
        
        Looks backward to find the LOAD_FAST/LOAD_NAME that loaded the container.
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return None
        
        # Look backward past the index load to find the container load
        # Stack at BINARY_SUBSCR: [..., container, index] -> TOS1=container, TOS=index
        j = idx - 1
        while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP'):
            j -= 1
        
        # Skip the index load
        if j >= 0 and self.instructions[j].opname in ('LOAD_CONST', 'LOAD_SMALL_INT', 'LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
            j -= 1
            while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP'):
                j -= 1
        
        # Now we should be at the container load
        if j >= 0:
            instr = self.instructions[j]
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                return instr.argval
        
        return None
    
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
            # ITERATION 702: Still record as guarded instance
            self.summary.record_bug_instance('NULL_PTR', is_guarded=True)
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
        
        # Exception barrier: check if AttributeError is caught at this site
        if not is_guarded and self._is_caught_exception(location.offset, 'NULL_PTR'):
            is_guarded = True  # Exception is handled locally
        
        # ITERATION 702: Use record_bug_instance for proper FP tracking
        self.summary.record_bug_instance('NULL_PTR', is_guarded)
        if not is_guarded:
            self.summary.may_raise.add(ExceptionType.ATTRIBUTE_ERROR)
            self.crash_locations.append(('NULL_PTR', location))
    
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
    
    def _is_slice_subscript(self, offset: int) -> bool:
        """
        Check if the subscript operation at offset is a slice operation.
        
        Slice operations NEVER raise IndexError - they just return empty/partial results.
        This is a fundamental Python language guarantee (slicing semantics).
        
        Patterns detected:
        1. LOAD_CONST slice(start, stop, step) - Python 3.14+ compile simple slices
        2. BUILD_SLICE opcode - Python's slice syntax with step a[i:j:k]
        3. BINARY_SLICE opcode - older Python slice syntax a[i:j]
        
        Returns True if this is a slice (should NOT flag BOUNDS - safe by Python semantics).
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return False
        
        instr = self.instructions[idx]
        
        # BINARY_SLICE opcode is always a slice, never raises IndexError
        if instr.opname == 'BINARY_SLICE':
            return True
        
        # For BINARY_OP [] or BINARY_SUBSCR, check preceding instructions
        # to determine if this is a slice or an index access
        
        # Check immediately preceding instruction(s), skipping CACHE/NOP
        for j in range(idx - 1, max(-1, idx - 6), -1):
            prev = self.instructions[j]
            
            # Skip cache and no-op instructions
            if prev.opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'COPY'):
                continue
            
            # BUILD_SLICE creates a slice object dynamically - always safe
            # Used for: s[::-1], s[::2], s[a:b:c] with variable step
            if prev.opname == 'BUILD_SLICE':
                return True
            
            # LOAD_CONST with slice object - Python 3.14+ optimization
            # Used for: s[1:3], s[:5], s[2:], etc.
            if prev.opname == 'LOAD_CONST':
                const_val = prev.argval
                if isinstance(const_val, slice):
                    return True
            
            # If we hit a non-slice-related instruction, stop looking
            # This means the subscript is an index, not a slice
            break
        
        return False
    
    def _is_safe_indexing(self, offset: int) -> bool:
        """
        Check if the subscript operation at offset is a safe indexing pattern.
        
        Safe indexing patterns that never raise IndexError:
        1. split()[0] - str.split() always returns at least one element
        2. split()[-1] on guaranteed non-empty (harder to detect)
        
        Python Language Guarantee (str.split):
        "If sep is not specified or is None... If the string is empty, 
        a list containing the empty string [''] is returned."
        
        Bytecode pattern for split()[0]:
        - LOAD_ATTR split
        - [LOAD_CONST separator]  (optional for split with separator)
        - CALL n
        - LOAD_SMALL_INT 0 / LOAD_CONST 0
        - BINARY_OP 26 ([])  <-- we're at this offset
        
        Returns True if this is safe indexing (should NOT flag BOUNDS).
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return False
        
        # Walk backward through instructions to find the pattern
        found_zero_index = False
        found_call = False
        call_idx = -1
        
        for j in range(idx - 1, max(-1, idx - 10), -1):
            instr = self.instructions[j]
            opname = instr.opname
            
            # Skip cache and no-op instructions
            if opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'COPY'):
                continue
            
            # First non-skip should be the index value
            if not found_zero_index:
                if opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and instr.argval == 0:
                    found_zero_index = True
                    continue  # Keep looking for CALL
                else:
                    return False  # Not an index 0 access
            
            # After finding index 0, look for CALL
            if not found_call:
                if opname == 'CALL':
                    found_call = True
                    call_idx = j
                    break  # Found CALL, now look for LOAD_ATTR split
                # If we hit something else before CALL, this isn't the pattern
                return False
        
        if not found_call or call_idx < 0:
            return False
        
        # Now look for LOAD_ATTR split before the CALL
        for k in range(call_idx - 1, max(-1, call_idx - 8), -1):
            attr_instr = self.instructions[k]
            if attr_instr.opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'COPY', 'LOAD_CONST'):
                # LOAD_CONST might be the separator argument
                continue
            if attr_instr.opname == 'LOAD_ATTR':
                # Check if it's split, rsplit, or splitlines
                attr_name = attr_instr.argval
                if isinstance(attr_name, str) and attr_name in ('split', 'rsplit', 'splitlines'):
                    return True
            # Stop on any other instruction
            break
        
        return False
    
    def _is_string_key_subscript(self, offset: int) -> bool:
        """
        Check if the subscript operation uses a string key (dict access pattern).
        
        Dict access like `user_data['email']` raises KeyError, not IndexError.
        We filter these out from BOUNDS bugs since:
        1. Dict keys are typically known/controlled in structured code
        2. This is a different error type (KeyError vs IndexError)
        3. Dict access patterns are often validated elsewhere
        
        Bytecode pattern:
        - LOAD_CONST 'string_key'  (or LOAD_FAST for string variable)
        - BINARY_OP 26 ([])  <-- we're at this offset
        
        Returns True if this is likely dict access with string key.
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return False
        
        # Walk backward to find the key being used
        for j in range(idx - 1, max(-1, idx - 6), -1):
            instr = self.instructions[j]
            opname = instr.opname
            
            # Skip cache and no-op instructions
            if opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'COPY'):
                continue
            
            # Check if the key is a string constant
            if opname == 'LOAD_CONST':
                # String constant key - likely dict access
                if isinstance(instr.argval, str):
                    return True
            
            # Stop on first non-skip instruction
            break
        
        return False
    
    def _has_divisor_validation_bytecode(self, idx: int, divisor_params: Set[int]) -> bool:
        """
        Check if divisor has validation in bytecode (assert x > 0, if x != 0, etc.).
        
        Looks backward for patterns like:
        - COMPARE_OP (>, !=, >=) followed by POP_JUMP_IF_FALSE (assert or raise)
        - COMPARE_OP with 0 constant
        """
        if not divisor_params or idx < 10:
            return False
        
        # Get divisor variable names
        divisor_vars = set()
        for param_idx in divisor_params:
            if param_idx < len(self.code.co_varnames):
                divisor_vars.add(self.code.co_varnames[param_idx])
        
        if not divisor_vars:
            return False
        
        # Scan backwards up to 20 instructions for validation
        for j in range(max(0, idx - 20), idx):
            instr = self.instructions[j]
            
            # Look for comparison operations
            if instr.opname == 'COMPARE_OP':
                # Get the comparison type
                cmp_op = instr.argval if hasattr(instr, 'argval') else instr.arg
                
                # Check if comparison is with 0 (validation)
                # Patterns: x > 0, x != 0, x >= 1
                if cmp_op in ('>', '!=', '>=', '<', '=='):
                    # Look at previous instructions to see if comparing divisor with 0
                    if j > 0:
                        prev = self.instructions[j-1]
                        # Check if comparing with 0
                        if prev.opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
                            if isinstance(prev.argval, (int, float)) and float(prev.argval) == 0.0:
                                # Found "var cmp 0" pattern
                                # Check if var is one of our divisors
                                if j > 1:
                                    var_load = self.instructions[j-2]
                                    if var_load.opname in ('LOAD_FAST', 'LOAD_DEREF'):
                                        var_name = var_load.argval
                                        if var_name in divisor_vars:
                                            # Found validation! Check if it's an assertion
                                            # Look for POP_JUMP_IF_FALSE or RAISE after comparison
                                            if j + 1 < len(self.instructions):
                                                next_instr = self.instructions[j+1]
                                                if next_instr.opname in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE', 
                                                                         'JUMP_IF_FALSE_OR_POP', 'RAISE_VARARGS'):
                                                    return True
            
            # Look for explicit max()/abs() calls (always return non-zero)
            elif instr.opname == 'CALL' or instr.opname == 'CALL_FUNCTION':
                # Check if calling max() or abs() on divisor
                if j > 0:
                    func_load = self.instructions[j-1]
                    if func_load.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                        if func_load.argval in ('max', 'abs'):
                            return True
        
        return False
    
    def _is_path_or_string_division_bytecode(self, idx: int) -> bool:
        """
        Check if the division at instruction index is Path division or string formatting.
        
        Path division: Path(...) / "name" - uses __truediv__ for path concatenation
        String formatting: "format %s" % args - uses __mod__ for string formatting
        
        Returns True if this is NOT a numeric division (should not flag DIV_ZERO).
        """
        if idx < 1 or idx >= len(self.instructions):
            return False
        
        instr = self.instructions[idx]
        
        # Only check division and modulo operations
        # BINARY_OP 11 = truediv (/), BINARY_OP 6 = mod (%)
        if instr.opname != 'BINARY_OP':
            return False
        
        op_code = instr.arg
        is_truediv = (op_code == 11)  # /
        is_mod = (op_code == 6)  # %
        
        if not (is_truediv or is_mod):
            return False
        
        # Look backwards for context
        # Stack at BINARY_OP: [left, right] -> left op right
        
        # For truediv, check if left operand is Path-like
        if is_truediv:
            # Look for Path patterns: LOAD_GLOBAL Path, LOAD_ATTR parent, LOAD_NAME __file__
            for j in range(max(0, idx - 10), idx):
                prev = self.instructions[j]
                # Path global
                if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME') and prev.argval == 'Path':
                    return True
                # Path attribute like .parent
                if prev.opname == 'LOAD_ATTR' and prev.argval in ('parent', 'resolve'):
                    return True
                # __file__ is typically a path
                if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME') and prev.argval == '__file__':
                    return True
        
        # For mod, check if left operand is a string (format string)
        if is_mod:
            # Look for string constant as left operand
            for j in range(max(0, idx - 5), idx):
                prev = self.instructions[j]
                if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, str):
                    # Check if it looks like a format string
                    if '%' in prev.argval:
                        return True
        
        return False
    
    # REMOVED: _has_len_guard_at pattern-matching hack
    # Bounds guards are now properly detected via GuardAnalyzer._check_bounds_guard_pattern
    # and checked via GuardState.has_bounds_safe() in _check_subscript

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
    
    INTERPROCEDURAL GUARD EXTENSION: After computing initial summaries,
    propagates guard facts across function boundaries:
    - If callee returns nonnull, caller's result variable is nonnull
    - If callee validates param before use, caller knows param was valid
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
        
        # INTERPROCEDURAL: Propagate guard facts across call graph
        self._propagate_interprocedural_guards()
        
        return self.summaries
    
    def _propagate_interprocedural_guards(self) -> None:
        """
        Propagate guard facts interprocedurally.
        
        Second pass that uses the computed summaries to:
        1. Mark call sites with callee return guarantees
        2. Reduce FP counts based on interprocedural reasoning
        """
        # For each function that has callers
        for func_name, summary in self.summaries.items():
            if not summary.return_guarantees:
                continue
            
            # If this function returns nonnull, all callers that store the
            # result get a nonnull guarantee for that variable
            callers = self.call_graph.get_callers(func_name)
            for caller_name in callers:
                caller_summary = self.summaries.get(caller_name)
                if caller_summary:
                    # Mark that this caller has access to nonnull return
                    # This information is used during bug checking
                    if 'nonnull' in summary.return_guarantees:
                        caller_summary.guarded_bugs.add(f'interprocedural_nonnull_from_{func_name}')
        
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
# COMBINED INTERPROCEDURAL SUMMARY
# ============================================================================
# Note: AST-based CrashSummaryComputer removed - use BytecodeCrashSummaryComputer

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
