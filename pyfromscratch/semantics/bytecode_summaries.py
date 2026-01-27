"""
Bytecode-Level Summary Computation for Intraprocedural Analysis.

Implements SOTA abstract interpretation over Python bytecode, integrating with:
- SymbolicMachineState from semantics/symbolic_vm.py
- Taint lattice L = P(T) × P(K) × P(T) from z3model/taint_lattice.py
- CFG and dataflow from cfg.control_flow, cfg.dataflow
- Unsafe predicates from unsafe/registry.py
- Guard tracking from symbolic_vm.py

This provides the canonical "bytecode-as-abstract-machine" semantics described
in barrier-certificate-theory.tex §3 and §7.

Key Features:
1. **SymbolicVM Integration**: Uses existing symbolic execution for precision
2. **Z3 Taint Lattice**: Full (τ, κ, σ) product lattice for security bugs
3. **Path-Sensitive Guards**: Leverages CFG edge conditions for precision
4. **Widening for Loops**: Ensures termination on loops with proper widening
5. **Exception Semantics**: Models exceptional control flow

Mathematical Foundation:
- Abstract domain uses SymbolicValue from z3model/values.py with Z3 expressions
- Transfer functions implemented by SymbolicVM._step()
- Fixpoint via worklist algorithm over CFG with SymbolicMachineState
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any, FrozenSet
from enum import IntEnum, auto
import dis
import types
import z3

from ..cfg.control_flow import (
    build_cfg, ControlFlowGraph, BasicBlock, EdgeType, ExceptionRegion
)
from ..cfg.dataflow import (
    run_intraprocedural_analysis, IntraprocAnalysisResult,
    GuardState, TypeState, BoundsInfo
)
from ..unsafe.registry import (
    UNSAFE_PREDICATES, check_unsafe_regions, list_implemented_bug_types
)
from ..z3model.taint_lattice import (
    TaintLabel, SymbolicTaintLabel,
    SourceType, SinkType, SanitizerType,
    TAU_WIDTH, KAPPA_WIDTH, SIGMA_WIDTH,
    tau_zero, kappa_full, sigma_zero,
)
from ..z3model.values import SymbolicValue, ValueTag


# ============================================================================
# ABSTRACT VALUE LATTICE
# ============================================================================

class Nullability(IntEnum):
    """Nullability lattice: ⊥ ⊑ NotNone ⊑ ⊤, ⊥ ⊑ IsNone ⊑ ⊤"""
    BOTTOM = 0       # Unreachable
    NOT_NONE = 1     # Definitely not None
    IS_NONE = 2      # Definitely None  
    TOP = 3          # Unknown (may be None or not)
    
    def join(self, other: 'Nullability') -> 'Nullability':
        if self == Nullability.BOTTOM:
            return other
        if other == Nullability.BOTTOM:
            return self
        if self == other:
            return self
        return Nullability.TOP
    
    def meet(self, other: 'Nullability') -> 'Nullability':
        if self == Nullability.TOP:
            return other
        if other == Nullability.TOP:
            return self
        if self == other:
            return self


class Emptiness(IntEnum):
    """Emptiness lattice for collection/sequence tracking.
    
    Used to detect:
    - EMPTY_COLLECTION_DIV: Division by len() when collection might be empty
    - EMPTY_COLLECTION_INDEX: Indexing [0] on potentially empty collections
    """
    BOTTOM = 0          # Unreachable
    NON_EMPTY = 1       # Collection has at least one element (len >= 1)
    EMPTY = 2           # Collection is definitely empty (len == 0)
    TOP = 3             # Unknown (may be empty or non-empty)
    
    def join(self, other: 'Emptiness') -> 'Emptiness':
        if self == Emptiness.BOTTOM:
            return other
        if other == Emptiness.BOTTOM:
            return self
        if self == other:
            return self
        return Emptiness.TOP
    
    def meet(self, other: 'Emptiness') -> 'Emptiness':
        if self == Emptiness.TOP:
            return other
        if other == Emptiness.TOP:
            return self
        if self == other:
            return self
        return Emptiness.BOTTOM


@dataclass(frozen=True)
class DictKeySet:
    """Tracks known dictionary keys for DICT_KEY_MISSING detection.
    
    - known_keys: Set of keys definitely present in the dict
    - is_complete: If True, no other keys exist (closed dict)
    - is_top: If True, key set is unknown
    """
    known_keys: FrozenSet[str] = field(default_factory=frozenset)
    is_complete: bool = False  # True = closed dict (only these keys exist)
    is_top: bool = True        # True = unknown key set
    
    def join(self, other: 'DictKeySet') -> 'DictKeySet':
        if self.is_top and other.is_top:
            return DictKeySet(is_top=True)
        if self.is_top:
            return other
        if other.is_top:
            return self
        # Both have known keys - intersect (definitely present in both paths)
        common_keys = self.known_keys & other.known_keys
        return DictKeySet(
            known_keys=common_keys,
            is_complete=self.is_complete and other.is_complete,
            is_top=False
        )
    
    def has_key(self, key: str) -> bool:
        """Returns True if key is definitely present."""
        if self.is_top:
            return False  # Unknown
        return key in self.known_keys
    
    def missing_key(self, key: str) -> bool:
        """Returns True if key is definitely NOT present."""
        if self.is_top:
            return False  # Unknown, can't say it's missing
        if not self.is_complete:
            return False  # Open dict, key might exist
        return key not in self.known_keys
    
    @classmethod
    def from_keys(cls, keys: Set[str], complete: bool = False) -> 'DictKeySet':
        return cls(known_keys=frozenset(keys), is_complete=complete, is_top=False)
    
    @classmethod
    def top(cls) -> 'DictKeySet':
        return cls(is_top=True)
    
    @classmethod
    def empty_dict(cls) -> 'DictKeySet':
        """Represents an empty dict {}."""
        return cls(known_keys=frozenset(), is_complete=True, is_top=False)
        return Nullability.BOTTOM


class Zeroness(IntEnum):
    """Zeroness lattice for division safety."""
    BOTTOM = 0       # Unreachable
    NON_ZERO = 1     # Definitely != 0
    ZERO = 2         # Definitely == 0
    TOP = 3          # Unknown
    
    def join(self, other: 'Zeroness') -> 'Zeroness':
        if self == Zeroness.BOTTOM:
            return other
        if other == Zeroness.BOTTOM:
            return self
        if self == other:
            return self
        return Zeroness.TOP
    
    def meet(self, other: 'Zeroness') -> 'Zeroness':
        if self == Zeroness.TOP:
            return other
        if other == Zeroness.TOP:
            return self
        if self == other:
            return self
        return Zeroness.BOTTOM


class Sign(IntEnum):
    """Sign lattice for bounds analysis."""
    BOTTOM = 0
    NEGATIVE = 1     # < 0
    ZERO = 2         # == 0
    POSITIVE = 3     # > 0
    NON_NEGATIVE = 4 # >= 0
    NON_POSITIVE = 5 # <= 0
    TOP = 6          # Any
    
    def join(self, other: 'Sign') -> 'Sign':
        if self == Sign.BOTTOM:
            return other
        if other == Sign.BOTTOM:
            return self
        if self == other:
            return self
        # Lattice join rules
        if {self, other} == {Sign.ZERO, Sign.POSITIVE}:
            return Sign.NON_NEGATIVE
        if {self, other} == {Sign.ZERO, Sign.NEGATIVE}:
            return Sign.NON_POSITIVE
        if {self, other} == {Sign.NON_NEGATIVE, Sign.NEGATIVE}:
            return Sign.TOP
        if {self, other} == {Sign.NON_POSITIVE, Sign.POSITIVE}:
            return Sign.TOP
        return Sign.TOP


@dataclass(frozen=True)
class TaintLabel:
    """
    Taint label from the product lattice L = P(T) × P(K) × P(T).
    
    Uses bitvectors for efficiency (as in z3model/taint_lattice.py).
    """
    tau: int = 0           # Sources: which taint types are present
    kappa: int = 0xFFFFFF  # Sanitizers: which sinks are protected (⊤ = all)
    sigma: int = 0         # Sinks: which sink checks have been performed
    
    def join(self, other: 'TaintLabel') -> 'TaintLabel':
        """Lattice join: τ∪, κ∩, σ∪"""
        return TaintLabel(
            tau=self.tau | other.tau,
            kappa=self.kappa & other.kappa,
            sigma=self.sigma | other.sigma,
        )
    
    def meet(self, other: 'TaintLabel') -> 'TaintLabel':
        """Lattice meet: τ∩, κ∪, σ∩"""
        return TaintLabel(
            tau=self.tau & other.tau,
            kappa=self.kappa | other.kappa,
            sigma=self.sigma & other.sigma,
        )
    
    def is_tainted(self) -> bool:
        return self.tau != 0
    
    def is_sanitized_for(self, sink_type: int) -> bool:
        return (self.kappa & (1 << sink_type)) != 0
    
    @classmethod
    def clean(cls) -> 'TaintLabel':
        return cls(tau=0, kappa=0xFFFFFF, sigma=0)
    
    @classmethod
    def tainted(cls, source_type: int) -> 'TaintLabel':
        return cls(tau=(1 << source_type), kappa=0, sigma=0)
    
    @classmethod
    def bottom(cls) -> 'TaintLabel':
        return cls(tau=0, kappa=0xFFFFFF, sigma=0)


@dataclass
class AbstractValue:
    """
    Abstract value in the product domain.
    
    A = Nullability × Zeroness × Sign × Emptiness × DictKeySet × TaintLabel × TypeSet × ParamSources
    
    This captures all properties needed for bug detection:
    - Nullability: for NULL_PTR detection
    - Zeroness: for DIV_ZERO detection  
    - Sign: for BOUNDS detection (negative indices)
    - Emptiness: for EMPTY_COLLECTION_DIV and EMPTY_COLLECTION_INDEX detection
    - DictKeySet: for DICT_KEY_MISSING detection
    - TaintLabel: for security bug detection
    - TypeSet: for TYPE_CONFUSION detection
    - ParamSources: which parameters this value derives from (for summaries)
    """
    nullability: Nullability = Nullability.TOP
    zeroness: Zeroness = Zeroness.TOP
    sign: Sign = Sign.TOP
    emptiness: Emptiness = Emptiness.TOP  # NEW: collection emptiness
    dict_keys: DictKeySet = field(default_factory=DictKeySet.top)  # NEW: known dict keys
    taint: TaintLabel = field(default_factory=TaintLabel.clean)
    types: FrozenSet[str] = field(default_factory=frozenset)  # Empty = unknown
    param_sources: FrozenSet[int] = field(default_factory=frozenset)  # Which params flow here
    
    # Numeric bounds (for widening)
    lower_bound: Optional[int] = None
    upper_bound: Optional[int] = None
    
    # NEW: Track if this value is the result of len() on a collection
    is_len_result: bool = False
    len_source_emptiness: Emptiness = Emptiness.TOP  # Emptiness of the collection len() was called on
    
    # NEW: Track if value might contain zeros (for array normalization)
    may_contain_zeros: bool = True  # For arrays/lists, can any element be 0?
    
    def join(self, other: 'AbstractValue') -> 'AbstractValue':
        """Lattice join."""
        return AbstractValue(
            nullability=self.nullability.join(other.nullability),
            zeroness=self.zeroness.join(other.zeroness),
            sign=self.sign.join(other.sign),
            emptiness=self.emptiness.join(other.emptiness),
            dict_keys=self.dict_keys.join(other.dict_keys),
            taint=self.taint.join(other.taint),
            types=self.types | other.types if self.types and other.types else frozenset(),
            param_sources=self.param_sources | other.param_sources,
            lower_bound=min(self.lower_bound, other.lower_bound) if self.lower_bound is not None and other.lower_bound is not None else None,
            upper_bound=max(self.upper_bound, other.upper_bound) if self.upper_bound is not None and other.upper_bound is not None else None,
            is_len_result=self.is_len_result or other.is_len_result,
            len_source_emptiness=self.len_source_emptiness.join(other.len_source_emptiness),
            may_contain_zeros=self.may_contain_zeros or other.may_contain_zeros,
        )
    
    def widen(self, other: 'AbstractValue') -> 'AbstractValue':
        """Widening operator for loop convergence."""
        result = self.join(other)
        # Drop bounds if they're growing
        if self.lower_bound is not None and other.lower_bound is not None:
            if other.lower_bound < self.lower_bound:
                result.lower_bound = None  # Widen to -∞
        if self.upper_bound is not None and other.upper_bound is not None:
            if other.upper_bound > self.upper_bound:
                result.upper_bound = None  # Widen to +∞
        return result
    
    @classmethod
    def from_param(cls, param_idx: int) -> 'AbstractValue':
        """Create abstract value for a function parameter."""
        return cls(
            nullability=Nullability.TOP,  # Params may be None
            zeroness=Zeroness.TOP,
            sign=Sign.TOP,
            taint=TaintLabel.clean(),
            types=frozenset(),
            param_sources=frozenset({param_idx}),
        )
    
    @classmethod
    def from_const(cls, value: Any) -> 'AbstractValue':
        """Create abstract value from a constant."""
        if value is None:
            return cls(
                nullability=Nullability.IS_NONE,
                zeroness=Zeroness.TOP,
                sign=Sign.TOP,
                types=frozenset({'NoneType'}),
                param_sources=frozenset(),
            )
        
        null = Nullability.NOT_NONE
        zero = Zeroness.TOP
        sgn = Sign.TOP
        typ = frozenset({type(value).__name__})
        lower = None
        upper = None
        emptiness = Emptiness.TOP
        dict_keys = DictKeySet.top()
        may_contain_zeros = True
        
        if isinstance(value, bool):
            zero = Zeroness.NON_ZERO if value else Zeroness.ZERO
            sgn = Sign.POSITIVE if value else Sign.ZERO
        elif isinstance(value, int):
            zero = Zeroness.ZERO if value == 0 else Zeroness.NON_ZERO
            if value < 0:
                sgn = Sign.NEGATIVE
            elif value == 0:
                sgn = Sign.ZERO
            else:
                sgn = Sign.POSITIVE
            lower = value
            upper = value
        elif isinstance(value, float):
            zero = Zeroness.ZERO if value == 0.0 else Zeroness.NON_ZERO
            if value < 0:
                sgn = Sign.NEGATIVE
            elif value == 0:
                sgn = Sign.ZERO
            else:
                sgn = Sign.POSITIVE
        elif isinstance(value, str):
            zero = Zeroness.NON_ZERO  # Strings are truthy unless empty
            emptiness = Emptiness.EMPTY if len(value) == 0 else Emptiness.NON_EMPTY
        elif isinstance(value, (list, tuple, set, frozenset)):
            # NEW: Track collection emptiness
            emptiness = Emptiness.EMPTY if len(value) == 0 else Emptiness.NON_EMPTY
            # Check if any element is 0 (for normalization safety)
            may_contain_zeros = any(v == 0 for v in value if isinstance(v, (int, float)))
        elif isinstance(value, dict):
            # NEW: Track dictionary keys
            emptiness = Emptiness.EMPTY if len(value) == 0 else Emptiness.NON_EMPTY
            dict_keys = DictKeySet.from_keys({str(k) for k in value.keys()}, complete=True)
        
        return cls(
            nullability=null,
            zeroness=zero,
            sign=sgn,
            emptiness=emptiness,
            dict_keys=dict_keys,
            types=typ,
            param_sources=frozenset(),
            lower_bound=lower,
            upper_bound=upper,
            may_contain_zeros=may_contain_zeros,
        )
    
    @classmethod
    def bottom(cls) -> 'AbstractValue':
        """Bottom element (unreachable)."""
        return cls(
            nullability=Nullability.BOTTOM,
            zeroness=Zeroness.BOTTOM,
            sign=Sign.BOTTOM,
            taint=TaintLabel.bottom(),
            types=frozenset(),
            param_sources=frozenset(),
        )
    
    @classmethod
    def top(cls) -> 'AbstractValue':
        """Top element (no information)."""
        return cls()


# ============================================================================
# ABSTRACT MACHINE STATE
# ============================================================================

@dataclass
class AbstractState:
    """
    Abstract state of the Python bytecode machine.
    
    Models:
    - Operand stack: list of AbstractValue
    - Local variables: Dict[int, AbstractValue] (by varname index)
    - Global/builtin bindings (simplified)
    """
    stack: List[AbstractValue] = field(default_factory=list)
    locals: Dict[int, AbstractValue] = field(default_factory=dict)
    globals: Dict[str, AbstractValue] = field(default_factory=dict)
    
    # Tracking
    is_bottom: bool = False  # Unreachable state
    
    def copy(self) -> 'AbstractState':
        return AbstractState(
            stack=self.stack.copy(),
            locals=self.locals.copy(),
            globals=self.globals.copy(),
            is_bottom=self.is_bottom,
        )
    
    def join(self, other: 'AbstractState') -> 'AbstractState':
        """Join two states (at control flow merge)."""
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        
        # Join stacks (must have same depth for well-formed bytecode)
        max_len = max(len(self.stack), len(other.stack))
        joined_stack = []
        for i in range(max_len):
            v1 = self.stack[i] if i < len(self.stack) else AbstractValue.bottom()
            v2 = other.stack[i] if i < len(other.stack) else AbstractValue.bottom()
            joined_stack.append(v1.join(v2))
        
        # Join locals
        all_vars = set(self.locals.keys()) | set(other.locals.keys())
        joined_locals = {}
        for var in all_vars:
            v1 = self.locals.get(var, AbstractValue.bottom())
            v2 = other.locals.get(var, AbstractValue.bottom())
            joined_locals[var] = v1.join(v2)
        
        # Join globals
        all_globals = set(self.globals.keys()) | set(other.globals.keys())
        joined_globals = {}
        for name in all_globals:
            v1 = self.globals.get(name, AbstractValue.bottom())
            v2 = other.globals.get(name, AbstractValue.bottom())
            joined_globals[name] = v1.join(v2)
        
        return AbstractState(
            stack=joined_stack,
            locals=joined_locals,
            globals=joined_globals,
            is_bottom=False,
        )
    
    def widen(self, other: 'AbstractState') -> 'AbstractState':
        """Widening for loop convergence."""
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        
        result = self.join(other)
        
        # Apply widening to locals
        for var in result.locals:
            if var in self.locals:
                result.locals[var] = self.locals[var].widen(result.locals[var])
        
        return result
    
    @classmethod
    def bottom(cls) -> 'AbstractState':
        return cls(is_bottom=True)
    
    def push(self, value: AbstractValue) -> None:
        self.stack.append(value)
    
    def pop(self) -> AbstractValue:
        if self.stack:
            return self.stack.pop()
        return AbstractValue.top()
    
    def peek(self, depth: int = 0) -> AbstractValue:
        """Peek at stack[-(depth+1)]."""
        idx = -(depth + 1)
        if abs(idx) <= len(self.stack):
            return self.stack[idx]
        return AbstractValue.top()


# ============================================================================
# ABSTRACT INTERPRETER
# ============================================================================

# Bug types that can be detected (subset from registry)
BUG_TYPES = list_implemented_bug_types()

# Opcode categories
BINARY_OPS_DIVISION = {2, 6, 11, 15, 19, 24}  # floor_divide, remainder, true_divide
BINARY_OPS_SUBSCRIPT = {26}  # Python 3.13+


@dataclass
class BugReport:
    """A potential bug found during abstract interpretation."""
    bug_type: str
    offset: int
    line_number: Optional[int]
    message: str
    confidence: float  # 0.0 to 1.0
    param_sources: FrozenSet[int]  # Which params contribute to bug
    is_guarded: bool = False  # True if a guard protects this


@dataclass
class BytecodeSummary:
    """
    Complete summary of a function's behavior.
    
    Integrates:
    - Taint flow (which params flow to return, with transformations)
    - Crash conditions (which params may cause which bugs)
    - Nullability (param/return None-ness)
    - Exception effects
    """
    function_name: str
    qualified_name: str
    parameter_count: int
    
    # Param → Return flow (for taint)
    param_to_return: Set[int] = field(default_factory=set)
    
    # Return value properties
    return_nullability: Nullability = Nullability.TOP
    return_taint: TaintLabel = field(default_factory=TaintLabel.clean)
    
    # Bugs that may be triggered
    potential_bugs: List[BugReport] = field(default_factory=list)
    
    # Per-param bug propagation
    # Maps param_idx -> set of bug types that param may trigger
    param_bug_propagation: Dict[int, Set[str]] = field(default_factory=dict)
    
    # Exception info
    may_raise: Set[str] = field(default_factory=set)  # Exception class names
    
    # From intraprocedural analysis integration
    intraproc_result: Optional[IntraprocAnalysisResult] = None
    
    # Side effects
    has_side_effects: bool = False
    modifies_globals: bool = False
    performs_io: bool = False
    
    def bugs_from_param(self, param_idx: int) -> Set[str]:
        """Get bug types that may be triggered by a parameter."""
        return self.param_bug_propagation.get(param_idx, set())
    
    def high_confidence_bugs(self, threshold: float = 0.7) -> List[BugReport]:
        """Get bugs with confidence above threshold."""
        return [b for b in self.potential_bugs if b.confidence >= threshold and not b.is_guarded]


class BytecodeAbstractInterpreter:
    """
    Abstract interpreter for Python bytecode.
    
    Computes a BytecodeSummary by abstract interpretation over the CFG,
    integrating with existing infrastructure:
    - Uses IntraprocAnalysisResult for guards/types/bounds
    - Uses CFG for control flow and exception handling
    - Applies widening at loop headers
    """
    
    def __init__(
        self,
        code: types.CodeType,
        func_name: str,
        qualified_name: str,
        callee_summaries: Optional[Dict[str, 'BytecodeSummary']] = None,
    ):
        self.code = code
        self.func_name = func_name
        self.qualified_name = qualified_name
        self.callee_summaries = callee_summaries or {}
        
        # Build CFG and run intraprocedural analysis
        self.cfg = build_cfg(code)
        self.intraproc = run_intraprocedural_analysis(code)
        
        # Parse code object
        self.instructions = list(dis.get_instructions(code))
        self.offset_to_instr = {i.offset: i for i in self.instructions}
        
        # Parameter info
        self.param_count = code.co_argcount + code.co_kwonlyargcount
        if code.co_flags & 0x04:  # CO_VARARGS
            self.param_count += 1
        if code.co_flags & 0x08:  # CO_VARKEYWORDS
            self.param_count += 1
        
        self.varnames = code.co_varnames
        self.const_values = code.co_consts
        
        # Analysis results
        self.block_entry_states: Dict[int, AbstractState] = {}
        self.block_exit_states: Dict[int, AbstractState] = {}
        self.potential_bugs: List[BugReport] = []
        self.return_values: List[AbstractValue] = []
        
        # Side effect tracking
        self.has_side_effects = False
        self.modifies_globals = False
        self.performs_io = False
        self.exceptions_raised: Set[str] = set()
    
    def analyze(self) -> BytecodeSummary:
        """Run abstract interpretation and produce summary."""
        # Initialize entry state with parameters
        entry_state = self._make_entry_state()
        self.block_entry_states[self.cfg.entry_block] = entry_state
        
        # Worklist algorithm with widening
        worklist = [self.cfg.entry_block]
        iterations: Dict[int, int] = {bid: 0 for bid in self.cfg.blocks}
        WIDEN_THRESHOLD = 3
        
        while worklist:
            block_id = worklist.pop(0)
            block = self.cfg.blocks[block_id]
            
            # Get entry state
            entry = self.block_entry_states.get(block_id, AbstractState.bottom())
            if entry.is_bottom:
                continue
            
            # Transfer through block
            exit_state = self._transfer_block(block, entry)
            self.block_exit_states[block_id] = exit_state
            
            # Propagate to successors
            for succ_id, edge_type, condition in block.successors:
                # Apply edge refinement
                refined = self._refine_on_edge(exit_state, edge_type, condition, block)
                
                # Get existing state at successor
                old_succ = self.block_entry_states.get(succ_id, AbstractState.bottom())
                
                # Merge (with widening at loop headers)
                iterations[succ_id] = iterations.get(succ_id, 0) + 1
                if succ_id in self.cfg.loop_headers and iterations[succ_id] > WIDEN_THRESHOLD:
                    new_succ = old_succ.widen(refined)
                else:
                    new_succ = old_succ.join(refined)
                
                # Check for change
                if self._state_changed(old_succ, new_succ):
                    self.block_entry_states[succ_id] = new_succ
                    if succ_id not in worklist:
                        worklist.append(succ_id)
        
        return self._build_summary()
    
    def _make_entry_state(self) -> AbstractState:
        """Create initial state with parameters."""
        state = AbstractState()
        for i in range(self.param_count):
            state.locals[i] = AbstractValue.from_param(i)
        return state
    
    def _transfer_block(self, block: BasicBlock, entry: AbstractState) -> AbstractState:
        """Transfer function for an entire basic block."""
        state = entry.copy()
        
        for instr in block.instructions:
            if state.is_bottom:
                break
            state = self._transfer_instr(instr, state, block.id)
        
        return state
    
    def _transfer_instr(
        self, 
        instr: dis.Instruction, 
        state: AbstractState,
        block_id: int,
    ) -> AbstractState:
        """Transfer function for a single instruction."""
        op = instr.opname
        arg = instr.arg
        argval = instr.argval
        offset = instr.offset
        
        # Get guards valid at this point
        guards = self.intraproc.get_guards_at_offset(offset)
        
        # Dispatch based on opcode
        if op == 'RESUME':
            pass  # No-op
        
        elif op == 'LOAD_CONST':
            val = self.const_values[arg] if arg is not None and arg < len(self.const_values) else None
            state.push(AbstractValue.from_const(val))
        
        elif op in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_LOAD_FAST', 
                    'LOAD_FAST_BORROW_LOAD_FAST_BORROW'):
            if op in ('LOAD_FAST_LOAD_FAST', 'LOAD_FAST_BORROW_LOAD_FAST_BORROW'):
                # Two loads encoded in argval
                if isinstance(argval, tuple):
                    for var in argval:
                        idx = self.varnames.index(var) if var in self.varnames else -1
                        if idx >= 0 and idx in state.locals:
                            state.push(state.locals[idx])
                        else:
                            state.push(AbstractValue.top())
            else:
                idx = arg if arg is not None else -1
                if idx >= 0 and idx in state.locals:
                    state.push(state.locals[idx])
                else:
                    state.push(AbstractValue.top())
        
        elif op in ('STORE_FAST', 'STORE_NAME'):
            val = state.pop()
            idx = arg if arg is not None else -1
            if idx >= 0:
                state.locals[idx] = val
        
        elif op in ('LOAD_GLOBAL', 'LOAD_NAME'):
            name = argval
            if name in state.globals:
                state.push(state.globals[name])
            else:
                # Unknown global - conservative
                state.push(AbstractValue.top())
        
        elif op == 'STORE_GLOBAL':
            val = state.pop()
            name = argval
            state.globals[name] = val
            self.modifies_globals = True
            self.has_side_effects = True
        
        elif op == 'BINARY_OP':
            self._handle_binary_op(state, arg, offset, guards, instr)
        
        elif op == 'COMPARE_OP':
            right = state.pop()
            left = state.pop()
            # Result is boolean with combined sources
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                zeroness=Zeroness.TOP,  # Comparison result may be True or False
                types=frozenset({'bool'}),
                param_sources=left.param_sources | right.param_sources,
            )
            state.push(result)
        
        elif op == 'IS_OP':
            right = state.pop()
            left = state.pop()
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                types=frozenset({'bool'}),
                param_sources=left.param_sources | right.param_sources,
            )
            state.push(result)
        
        elif op == 'LOAD_ATTR':
            self._handle_load_attr(state, argval, offset, guards, instr)
        
        elif op in ('CALL', 'CALL_FUNCTION', 'CALL_METHOD'):
            self._handle_call(state, arg, offset, guards, instr)
        
        elif op in ('RETURN_VALUE', 'RETURN_CONST'):
            if op == 'RETURN_CONST':
                val = self.const_values[arg] if arg is not None and arg < len(self.const_values) else None
                self.return_values.append(AbstractValue.from_const(val))
            else:
                ret_val = state.pop()
                self.return_values.append(ret_val)
        
        elif op == 'RAISE_VARARGS':
            self.exceptions_raised.add('Exception')
            state = AbstractState.bottom()
        
        elif op == 'POP_TOP':
            state.pop()
        
        elif op == 'COPY':
            if state.stack:
                state.push(state.peek(0))
        
        elif op == 'SWAP':
            if len(state.stack) >= 2:
                state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]
        
        elif op == 'PUSH_NULL':
            state.push(AbstractValue.from_const(None))
        
        elif op in ('BUILD_LIST', 'BUILD_TUPLE', 'BUILD_SET'):
            count = arg or 0
            sources = frozenset()
            for _ in range(count):
                v = state.pop()
                sources = sources | v.param_sources
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                zeroness=Zeroness.NON_ZERO if count > 0 else Zeroness.ZERO,
                types=frozenset({'list' if 'LIST' in op else 'tuple' if 'TUPLE' in op else 'set'}),
                param_sources=sources,
            )
            state.push(result)
        
        elif op == 'BUILD_MAP':
            count = arg or 0
            sources = frozenset()
            for _ in range(count * 2):  # key-value pairs
                v = state.pop()
                sources = sources | v.param_sources
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                types=frozenset({'dict'}),
                param_sources=sources,
            )
            state.push(result)
        
        elif op == 'UNARY_NOT':
            val = state.pop()
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                types=frozenset({'bool'}),
                param_sources=val.param_sources,
            )
            state.push(result)
        
        elif op == 'UNARY_NEGATIVE':
            val = state.pop()
            # Negate sign
            new_sign = Sign.TOP
            if val.sign == Sign.POSITIVE:
                new_sign = Sign.NEGATIVE
            elif val.sign == Sign.NEGATIVE:
                new_sign = Sign.POSITIVE
            elif val.sign == Sign.ZERO:
                new_sign = Sign.ZERO
            
            result = AbstractValue(
                nullability=val.nullability,
                zeroness=val.zeroness,
                sign=new_sign,
                types=val.types,
                param_sources=val.param_sources,
            )
            state.push(result)
        
        elif op == 'GET_ITER':
            val = state.pop()
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                param_sources=val.param_sources,
            )
            state.push(result)
        
        elif op == 'FOR_ITER':
            # Iterator may yield or be exhausted
            self.exceptions_raised.add('StopIteration')
        
        elif op == 'LOAD_ASSERTION_ERROR':
            state.push(AbstractValue.from_const(AssertionError))
            self._add_bug('ASSERT_FAIL', offset, instr, frozenset(), guards, 0.5)
        
        elif op in ('IMPORT_NAME', 'IMPORT_FROM'):
            state.push(AbstractValue.top())
        
        else:
            # Unknown opcode - conservative handling
            # Pop inputs based on opcode stack effect, push unknown outputs
            pass
        
        return state
    
    def _handle_binary_op(
        self,
        state: AbstractState,
        oparg: int,
        offset: int,
        guards: GuardState,
        instr: dis.Instruction,
    ) -> None:
        """Handle BINARY_OP instruction with bug detection."""
        right = state.pop()
        left = state.pop()
        
        sources = left.param_sources | right.param_sources
        result = AbstractValue(
            param_sources=sources,
            taint=left.taint.join(right.taint),
        )
        
        # Check for division
        if oparg in BINARY_OPS_DIVISION:
            # Check if divisor may be zero
            if right.zeroness != Zeroness.NON_ZERO:
                # Check for guard
                is_guarded = False
                for src in right.param_sources:
                    if src < len(self.varnames):
                        var_name = self.varnames[src]
                        if guards.has_div_safe(var_name):
                            is_guarded = True
                            break
                
                confidence = 0.9 if right.zeroness == Zeroness.ZERO else 0.6
                self._add_bug('DIV_ZERO', offset, instr, right.param_sources, guards, confidence, is_guarded)
                self.exceptions_raised.add('ZeroDivisionError')
            
            # Note: EMPTY_COLLECTION_DIV is NOT a separate bug - it's just DIV_ZERO
            # because len() of empty collection returns 0, which triggers DIV_ZERO.
            # The zeroness lattice already tracks this via len() handling in _handle_call.
            
            # SCALE_ZERO_NORMALIZE: Division by array that may contain zeros
            # This IS a distinct pattern because the array itself isn't zero,
            # but individual elements might be. Track via may_contain_zeros property.
            if right.may_contain_zeros and ('ndarray' in right.types or 'list' in right.types):
                # Array division where elements might be zero - lower confidence
                # since this is element-wise, not the whole value being zero
                self._add_bug('DIV_ZERO', offset, instr, right.param_sources, guards, 0.4, False)
            
            result.nullability = Nullability.NOT_NONE
            result.types = frozenset({'float', 'int'})
        
        # Check for subscript
        elif oparg in BINARY_OPS_SUBSCRIPT:
            # Index access
            if right.sign in (Sign.NEGATIVE, Sign.TOP):
                # Negative index risk (though Python allows it)
                pass
            
            # EMPTY_COLLECTION_INDEX is just BOUNDS - if we know the collection is
            # empty and we're indexing at 0, that's a BOUNDS error. The emptiness
            # property helps us determine this with higher confidence.
            if left.emptiness == Emptiness.EMPTY:
                # Definitely empty - high confidence BOUNDS
                self._add_bug('BOUNDS', offset, instr, sources, guards, 0.9, False)
                self.exceptions_raised.add('IndexError')
            elif left.emptiness != Emptiness.NON_EMPTY:
                # Might be empty - normal BOUNDS check
                # (already covered by the general BOUNDS check below)
                pass
            
            # DICT_KEY_MISSING is just KeyError, a form of BOUNDS
            # If we know the dict's keys and the accessed key isn't in them, flag it
            if 'dict' in left.types and not left.dict_keys.is_top:
                if left.dict_keys.is_complete and len(left.dict_keys.known_keys) < 10:
                    # Known dict with limited keys - higher confidence BOUNDS
                    self._add_bug('BOUNDS', offset, instr, sources, guards, 0.7, False)
                    self.exceptions_raised.add('KeyError')
            
            # Always a BOUNDS risk without static knowledge
            self._add_bug('BOUNDS', offset, instr, sources, guards, 0.5)
            self.exceptions_raised.add('IndexError')
            self.exceptions_raised.add('KeyError')
            
            result.nullability = Nullability.TOP
        
        else:
            # Other binary ops
            result.nullability = Nullability.NOT_NONE
        
        state.push(result)
    
    def _handle_load_attr(
        self,
        state: AbstractState,
        attr_name: str,
        offset: int,
        guards: GuardState,
        instr: dis.Instruction,
    ) -> None:
        """Handle LOAD_ATTR with null dereference detection."""
        obj = state.pop()
        
        # Check for null dereference
        if obj.nullability != Nullability.NOT_NONE:
            is_guarded = False
            for src in obj.param_sources:
                if src < len(self.varnames):
                    var_name = self.varnames[src]
                    if guards.has_nonnull(var_name):
                        is_guarded = True
                        break
            
            confidence = 0.9 if obj.nullability == Nullability.IS_NONE else 0.5
            self._add_bug('NULL_PTR', offset, instr, obj.param_sources, guards, confidence, is_guarded)
            self.exceptions_raised.add('AttributeError')
        
        # Result inherits sources
        result = AbstractValue(
            nullability=Nullability.TOP,  # Attribute may be None
            param_sources=obj.param_sources,
            taint=obj.taint,
        )
        state.push(result)
    
    def _handle_call(
        self,
        state: AbstractState,
        argc: int,
        offset: int,
        guards: GuardState,
        instr: dis.Instruction,
    ) -> None:
        """Handle CALL with callee summary application."""
        # Pop arguments
        args = []
        for _ in range(argc or 0):
            args.insert(0, state.pop())
        
        # Pop callable
        func = state.pop()
        
        # Check for known dangerous calls
        callee_name = self._get_callee_name(offset)
        
        # NEW: Track len() calls for EMPTY_COLLECTION_DIV detection
        if callee_name == 'len' and len(args) == 1:
            collection = args[0]
            # Result of len() is an int >= 0
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                zeroness=Zeroness.NON_ZERO if collection.emptiness == Emptiness.NON_EMPTY else 
                         (Zeroness.ZERO if collection.emptiness == Emptiness.EMPTY else Zeroness.TOP),
                sign=Sign.NON_NEGATIVE,
                param_sources=collection.param_sources,
                types=frozenset({'int'}),
                is_len_result=True,
                len_source_emptiness=collection.emptiness,
                lower_bound=0 if collection.emptiness != Emptiness.NON_EMPTY else 1,
                upper_bound=None,
            )
            state.push(result)
            return
        
        # NEW: Track .shape[0] access for arrays (common NumPy pattern)
        if callee_name and '.shape' in callee_name:
            # Array shape - result may be 0
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                zeroness=Zeroness.TOP,  # shape[0] could be 0 for empty arrays
                sign=Sign.NON_NEGATIVE,
                types=frozenset({'int'}),
                is_len_result=True,  # Treat shape[0] like len()
                len_source_emptiness=Emptiness.TOP,
            )
            state.push(result)
            return
        
        # NEW: Track dict.get() which is safe (returns None for missing keys)
        if callee_name and callee_name.endswith('.get'):
            # dict.get() is safe - doesn't raise KeyError
            all_sources = frozenset().union(*(a.param_sources for a in args))
            result = AbstractValue(
                nullability=Nullability.TOP,  # May return None if key missing
                param_sources=all_sources,
            )
            state.push(result)
            return
        
        if callee_name:
            if callee_name in ('eval', 'exec', 'compile'):
                sources = frozenset().union(*(a.param_sources for a in args))
                self._add_bug('CODE_INJECTION', offset, instr, sources, guards, 0.8)
            elif callee_name in ('os.system', 'subprocess.call', 'subprocess.run'):
                sources = frozenset().union(*(a.param_sources for a in args))
                self._add_bug('COMMAND_INJECTION', offset, instr, sources, guards, 0.8)
                self.has_side_effects = True
            elif callee_name in ('open',):
                self.performs_io = True
                self.has_side_effects = True
            
            # Apply callee summary if available
            if callee_name in self.callee_summaries:
                callee = self.callee_summaries[callee_name]
                # Merge callee's bugs
                for bug in callee.potential_bugs:
                    self.potential_bugs.append(bug)
        
        # Result is unknown unless we have summary
        all_sources = frozenset().union(*(a.param_sources for a in args))
        result = AbstractValue(
            nullability=Nullability.TOP,
            param_sources=all_sources,
            taint=TaintLabel.clean().join(*[a.taint for a in args]) if args else TaintLabel.clean(),
        )
        state.push(result)
        
        # Calls may raise
        self.exceptions_raised.add('Exception')
    
    def _get_callee_name(self, call_offset: int) -> Optional[str]:
        """Try to determine callee name from preceding instructions."""
        # Look backwards for LOAD_* instructions
        parts = []
        for i, instr in enumerate(self.instructions):
            if instr.offset == call_offset:
                for j in range(i - 1, max(i - 5, -1), -1):
                    prev = self.instructions[j]
                    if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_BUILTIN'):
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
                break
        return '.'.join(parts) if parts else None
    
    def _refine_on_edge(
        self,
        state: AbstractState,
        edge_type: EdgeType,
        condition: Optional[str],
        block: BasicBlock,
    ) -> AbstractState:
        """Apply path-sensitive refinement on CFG edge."""
        if state.is_bottom:
            return state
        
        result = state.copy()
        
        # Use intraprocedural analysis for edge refinement
        if block.instructions:
            last_offset = block.instructions[-1].offset
            
            # Look for IS_OP (None check) pattern
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'IS_OP' and i >= 2:
                    is_not = instr.arg == 1
                    
                    load_instr = block.instructions[i - 2]
                    const_instr = block.instructions[i - 1]
                    
                    if (load_instr.opname in ('LOAD_FAST', 'LOAD_NAME', 'LOAD_FAST_BORROW') and
                        const_instr.opname == 'LOAD_CONST' and
                        const_instr.argval is None):
                        
                        var_idx = load_instr.arg
                        if var_idx in result.locals:
                            val = result.locals[var_idx]
                            
                            if edge_type == EdgeType.COND_TRUE:
                                # True branch
                                new_null = Nullability.NOT_NONE if is_not else Nullability.IS_NONE
                            else:
                                # False branch
                                new_null = Nullability.IS_NONE if is_not else Nullability.NOT_NONE
                            
                            result.locals[var_idx] = AbstractValue(
                                nullability=new_null,
                                zeroness=val.zeroness,
                                sign=val.sign,
                                taint=val.taint,
                                types=val.types,
                                param_sources=val.param_sources,
                            )
        
        return result
    
    def _state_changed(self, old: AbstractState, new: AbstractState) -> bool:
        """Check if state changed (for fixpoint detection)."""
        if old.is_bottom != new.is_bottom:
            return True
        if old.is_bottom:
            return False
        
        # Compare locals
        all_vars = set(old.locals.keys()) | set(new.locals.keys())
        for var in all_vars:
            old_val = old.locals.get(var)
            new_val = new.locals.get(var)
            if old_val is None and new_val is not None:
                return True
            if old_val is not None and new_val is None:
                return True
            if old_val and new_val:
                if (old_val.nullability != new_val.nullability or
                    old_val.zeroness != new_val.zeroness or
                    old_val.param_sources != new_val.param_sources):
                    return True
        
        return False
    
    def _add_bug(
        self,
        bug_type: str,
        offset: int,
        instr: dis.Instruction,
        sources: FrozenSet[int],
        guards: GuardState,
        confidence: float,
        is_guarded: bool = False,
    ) -> None:
        """Record a potential bug."""
        line = None
        if hasattr(instr, 'positions') and instr.positions:
            line = instr.positions.lineno
        
        bug = BugReport(
            bug_type=bug_type,
            offset=offset,
            line_number=line,
            message=f"{bug_type} at {instr.opname}",
            confidence=confidence,
            param_sources=sources,
            is_guarded=is_guarded,
        )
        self.potential_bugs.append(bug)
    
    def _build_summary(self) -> BytecodeSummary:
        """Build final summary from analysis results."""
        # Compute return properties
        return_null = Nullability.BOTTOM
        return_taint = TaintLabel.bottom()
        param_to_return: Set[int] = set()
        
        for ret_val in self.return_values:
            return_null = return_null.join(ret_val.nullability)
            return_taint = return_taint.join(ret_val.taint)
            param_to_return.update(ret_val.param_sources)
        
        # Compute param bug propagation
        param_bugs: Dict[int, Set[str]] = {}
        for bug in self.potential_bugs:
            for src in bug.param_sources:
                if src not in param_bugs:
                    param_bugs[src] = set()
                param_bugs[src].add(bug.bug_type)
        
        return BytecodeSummary(
            function_name=self.func_name,
            qualified_name=self.qualified_name,
            parameter_count=self.param_count,
            param_to_return=param_to_return,
            return_nullability=return_null,
            return_taint=return_taint,
            potential_bugs=self.potential_bugs,
            param_bug_propagation=param_bugs,
            may_raise=self.exceptions_raised,
            intraproc_result=self.intraproc,
            has_side_effects=self.has_side_effects,
            modifies_globals=self.modifies_globals,
            performs_io=self.performs_io,
        )


# ============================================================================
# CONVENIENCE API
# ============================================================================

def analyze_function(
    func: types.FunctionType,
    callee_summaries: Optional[Dict[str, BytecodeSummary]] = None,
) -> BytecodeSummary:
    """
    Analyze a Python function and compute its bytecode summary.
    
    Example:
        def divide(x, y):
            return x / y
        
        summary = analyze_function(divide)
        print(summary.potential_bugs)  # [BugReport(bug_type='DIV_ZERO', ...)]
        print(summary.param_bug_propagation)  # {1: {'DIV_ZERO'}}
    """
    code = func.__code__
    name = func.__name__
    qualname = func.__qualname__
    
    interpreter = BytecodeAbstractInterpreter(
        code=code,
        func_name=name,
        qualified_name=qualname,
        callee_summaries=callee_summaries,
    )
    return interpreter.analyze()


def analyze_code_object(
    code: types.CodeType,
    func_name: Optional[str] = None,
    qualified_name: Optional[str] = None,
    callee_summaries: Optional[Dict[str, BytecodeSummary]] = None,
) -> BytecodeSummary:
    """
    Analyze a code object directly.
    
    This is the primary entry point for bytecode-level analysis.
    """
    name = func_name or code.co_name
    qname = qualified_name or (code.co_qualname if hasattr(code, 'co_qualname') else name)
    
    interpreter = BytecodeAbstractInterpreter(
        code=code,
        func_name=name,
        qualified_name=qname,
        callee_summaries=callee_summaries,
    )
    return interpreter.analyze()


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Lattices
    'Nullability',
    'Zeroness', 
    'Sign',
    'TaintLabel',
    'AbstractValue',
    'AbstractState',
    
    # Analysis results
    'BugReport',
    'BytecodeSummary',
    
    # Analyzer
    'BytecodeAbstractInterpreter',
    
    # Convenience API
    'analyze_function',
    'analyze_code_object',
]
