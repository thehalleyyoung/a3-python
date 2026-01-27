"""
Control Flow Graph for Python bytecode, including exceptional edges.

Implements the CFG extraction described in barrier-certificate-theory.tex §6.3:
- Normal edges: JUMP, JUMP_IF_*, fallthrough, RETURN_VALUE
- Exceptional edges: any instruction that may raise can transfer to a handler

The CFG provides:
1. Basic block structure
2. Dominance analysis for guard inference
3. Exception handler regions (for WillCatchAt predicates)
4. Loop detection for ranking function synthesis
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
import dis
import types
from enum import Enum, auto


class EdgeType(Enum):
    """Type of CFG edge."""
    FALLTHROUGH = auto()      # Normal sequential execution
    JUMP = auto()             # Unconditional jump
    COND_TRUE = auto()        # Conditional branch (true case)
    COND_FALSE = auto()       # Conditional branch (false case)
    EXCEPTION = auto()        # Exception raised → handler
    RETURN = auto()           # Function return
    YIELD = auto()            # Generator yield
    RAISE = auto()            # Explicit raise (to exception handler or exit)


@dataclass
class BasicBlock:
    """
    A basic block in the CFG.
    
    Single entry, single exit under normal control flow.
    May have multiple exception edges.
    """
    id: int
    start_offset: int
    end_offset: int  # Exclusive
    instructions: List[dis.Instruction]
    
    # Successor edges: (target_block_id, edge_type, guard_condition)
    # guard_condition is the condition that must hold for this edge (for COND_TRUE/COND_FALSE)
    successors: List[Tuple[int, EdgeType, Optional[str]]] = field(default_factory=list)
    
    # Predecessor block IDs
    predecessors: List[int] = field(default_factory=list)
    
    # Exception handler target (if any instruction in this block can raise)
    exception_handler: Optional[int] = None
    
    # Variables loaded/stored in this block
    loads: Set[str] = field(default_factory=set)
    stores: Set[str] = field(default_factory=set)
    
    # Guard checks performed in this block
    # Each entry: (var_name, guard_type, check_offset)
    guard_checks: List[Tuple[str, str, int]] = field(default_factory=list)
    
    @property
    def is_entry(self) -> bool:
        """Is this the entry block?"""
        return self.start_offset == 0
    
    @property
    def is_exit(self) -> bool:
        """Is this an exit block (returns or raises unhandled)?"""
        if not self.instructions:
            return False
        last_instr = self.instructions[-1]
        return last_instr.opname in ('RETURN_VALUE', 'RETURN_CONST')
    
    @property
    def may_raise(self) -> bool:
        """Does this block contain any instruction that may raise?"""
        # Most operations in Python can potentially raise
        # We're conservative: only RESUME, NOP, and some other pure ops are safe
        safe_ops = {'RESUME', 'NOP', 'CACHE', 'POP_TOP', 'COPY', 'SWAP', 
                    'EXTENDED_ARG', 'PUSH_NULL', 'END_FOR', 'END_SEND'}
        for instr in self.instructions:
            if instr.opname not in safe_ops:
                return True
        return False


@dataclass  
class ExceptionRegion:
    """
    An exception handler region in the bytecode.
    
    Corresponds to a try/except/finally block.
    """
    start_offset: int        # First instruction covered
    end_offset: int          # Last instruction covered (exclusive)
    handler_offset: int      # Handler entry point
    depth: int               # Nesting depth
    exception_types: List[str] = field(default_factory=list)  # Types caught (empty = catch-all)
    
    def contains_offset(self, offset: int) -> bool:
        """Check if an instruction offset is within this region."""
        return self.start_offset <= offset < self.end_offset


@dataclass
class ControlFlowGraph:
    """
    Complete CFG for a Python function/module.
    
    Provides:
    - Basic block structure
    - Dominance tree
    - Exception handler regions
    - Loop headers and back edges
    """
    code: types.CodeType
    blocks: Dict[int, BasicBlock]  # block_id -> BasicBlock
    entry_block: int
    exit_blocks: List[int]
    
    # Exception regions from exception table
    exception_regions: List[ExceptionRegion] = field(default_factory=list)
    
    # Dominance info (populated by compute_dominance)
    dominators: Dict[int, Set[int]] = field(default_factory=dict)  # block -> set of dominators
    immediate_dominator: Dict[int, int] = field(default_factory=dict)  # block -> idom
    
    # Post-dominance info (for control dependence)
    post_dominators: Dict[int, Set[int]] = field(default_factory=dict)
    
    # Loop info
    loop_headers: Set[int] = field(default_factory=set)  # block IDs that are loop headers
    back_edges: List[Tuple[int, int]] = field(default_factory=list)  # (from_block, to_block)
    
    # Offset to block mapping
    offset_to_block: Dict[int, int] = field(default_factory=dict)  # instruction offset -> block_id
    
    def get_block_for_offset(self, offset: int) -> Optional[BasicBlock]:
        """Get the basic block containing a given instruction offset."""
        block_id = self.offset_to_block.get(offset)
        if block_id is not None:
            return self.blocks.get(block_id)
        return None
    
    def get_exception_handler(self, offset: int) -> Optional[ExceptionRegion]:
        """Get the innermost exception handler covering an offset."""
        best = None
        for region in self.exception_regions:
            if region.contains_offset(offset):
                if best is None or region.depth > best.depth:
                    best = region
        return best
    
    def is_dominated_by(self, block: int, dominator: int) -> bool:
        """Check if 'dominator' dominates 'block'."""
        return dominator in self.dominators.get(block, set())
    
    def dominates_all_paths_to(self, check_block: int, use_block: int) -> bool:
        """
        Check if check_block dominates all paths to use_block.
        
        This is used for guard inference: if a type/None check in check_block
        dominates use_block, then the guard is established at use_block.
        """
        return self.is_dominated_by(use_block, check_block)


def build_cfg(code: types.CodeType) -> ControlFlowGraph:
    """
    Build a control flow graph from a code object.
    
    Algorithm:
    1. Parse exception table to identify protected regions
    2. Find basic block boundaries (leaders)
    3. Build blocks and edges
    4. Compute dominance
    5. Detect loops
    
    Returns:
        Complete CFG with all analysis results
    """
    instructions = list(dis.get_instructions(code))
    if not instructions:
        # Empty code object
        empty_block = BasicBlock(0, 0, 0, [])
        return ControlFlowGraph(
            code=code,
            blocks={0: empty_block},
            entry_block=0,
            exit_blocks=[0]
        )
    
    # Step 1: Parse exception table
    exception_regions = _parse_exception_regions(code)
    
    # Step 2: Find block leaders
    leaders = _find_leaders(instructions, exception_regions)
    
    # Step 3: Build basic blocks
    blocks, offset_to_block = _build_blocks(instructions, leaders)
    
    # Step 4: Connect edges
    _connect_edges(blocks, offset_to_block, exception_regions)
    
    # Step 5: Analyze variable accesses
    _analyze_variables(blocks)
    
    # Create CFG
    entry_block = 0  # First block is always entry
    exit_blocks = [bid for bid, blk in blocks.items() if blk.is_exit]
    
    cfg = ControlFlowGraph(
        code=code,
        blocks=blocks,
        entry_block=entry_block,
        exit_blocks=exit_blocks,
        exception_regions=exception_regions,
        offset_to_block=offset_to_block
    )
    
    # Step 6: Compute dominance
    _compute_dominance(cfg)
    
    # Step 7: Detect loops
    _detect_loops(cfg)
    
    return cfg


def _parse_exception_regions(code: types.CodeType) -> List[ExceptionRegion]:
    """Parse Python 3.11+ exception table into ExceptionRegion objects."""
    regions = []
    
    import sys
    if sys.version_info >= (3, 11):
        try:
            from dis import _parse_exception_table
            for start, end, target, depth, lasti in _parse_exception_table(code):
                region = ExceptionRegion(
                    start_offset=start,
                    end_offset=end,
                    handler_offset=target,
                    depth=depth
                )
                regions.append(region)
        except Exception:
            pass
    
    return regions


def _find_leaders(
    instructions: List[dis.Instruction],
    exception_regions: List[ExceptionRegion]
) -> Set[int]:
    """
    Find basic block leaders (first instruction of each block).
    
    A leader is:
    - First instruction of the function
    - Target of any jump
    - Instruction following a jump/branch
    - Handler entry point
    """
    leaders = {0}  # First instruction is always a leader
    
    # Add exception handler targets as leaders
    for region in exception_regions:
        leaders.add(region.handler_offset)
    
    for i, instr in enumerate(instructions):
        # Check for jump instructions
        if instr.opname in (
            'JUMP_FORWARD',
            'JUMP_BACKWARD',
            'JUMP_BACKWARD_NO_INTERRUPT',
            'JUMP',
            'POP_JUMP_IF_TRUE',
            'POP_JUMP_IF_FALSE',
            'POP_JUMP_IF_NONE',
            'POP_JUMP_IF_NOT_NONE',
            'POP_JUMP_FORWARD_IF_TRUE',
            'POP_JUMP_FORWARD_IF_FALSE',
            'POP_JUMP_FORWARD_IF_NONE',
            'POP_JUMP_FORWARD_IF_NOT_NONE',
            'POP_JUMP_BACKWARD_IF_TRUE',
            'POP_JUMP_BACKWARD_IF_FALSE',
            'POP_JUMP_BACKWARD_IF_NONE',
            'POP_JUMP_BACKWARD_IF_NOT_NONE',
            'FOR_ITER',
            'SEND',
        ):
            # Jump target is a leader
            if instr.argval is not None:
                leaders.add(instr.argval)
            # Instruction after jump is a leader (for conditional jumps)
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].offset)
        
        # Return/raise end a block
        if instr.opname in ('RETURN_VALUE', 'RETURN_CONST', 'RAISE_VARARGS', 'RERAISE'):
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].offset)
    
    return leaders


def _build_blocks(
    instructions: List[dis.Instruction],
    leaders: Set[int]
) -> Tuple[Dict[int, BasicBlock], Dict[int, int]]:
    """Build basic blocks from instructions and leaders."""
    blocks = {}
    offset_to_block = {}
    
    sorted_leaders = sorted(leaders)
    
    for i, leader_offset in enumerate(sorted_leaders):
        # Find end of this block
        if i + 1 < len(sorted_leaders):
            end_offset = sorted_leaders[i + 1]
        else:
            # Last block extends to end
            end_offset = instructions[-1].offset + 2
        
        # Collect instructions in this block
        block_instrs = [
            instr for instr in instructions
            if leader_offset <= instr.offset < end_offset
        ]
        
        block = BasicBlock(
            id=i,
            start_offset=leader_offset,
            end_offset=end_offset,
            instructions=block_instrs
        )
        blocks[i] = block
        
        # Map offsets to block
        for instr in block_instrs:
            offset_to_block[instr.offset] = i
    
    return blocks, offset_to_block


def _connect_edges(
    blocks: Dict[int, BasicBlock],
    offset_to_block: Dict[int, int],
    exception_regions: List[ExceptionRegion]
):
    """Connect blocks with normal and exceptional edges."""
    
    for block in blocks.values():
        if not block.instructions:
            continue
        
        last_instr = block.instructions[-1]
        
        # Determine successor edges based on last instruction
        if last_instr.opname in ('RETURN_VALUE', 'RETURN_CONST'):
            # No successors (exit block)
            pass
        
        elif last_instr.opname in ('JUMP_FORWARD', 'JUMP_BACKWARD', 'JUMP_BACKWARD_NO_INTERRUPT', 'JUMP'):
            # Unconditional jump
            target = last_instr.argval
            if target in offset_to_block:
                target_block = offset_to_block[target]
                block.successors.append((target_block, EdgeType.JUMP, None))
                blocks[target_block].predecessors.append(block.id)
        
        elif last_instr.opname.startswith('POP_JUMP'):
            # Conditional jump
            target = last_instr.argval
            if target in offset_to_block:
                target_block = offset_to_block[target]
                
                # Determine true/false based on opname
                if 'IF_TRUE' in last_instr.opname or 'IF_NOT_NONE' in last_instr.opname:
                    block.successors.append((target_block, EdgeType.COND_TRUE, None))
                else:
                    block.successors.append((target_block, EdgeType.COND_FALSE, None))
                blocks[target_block].predecessors.append(block.id)
            
            # Fallthrough edge
            fallthrough_offset = block.end_offset
            if fallthrough_offset in offset_to_block:
                ft_block = offset_to_block[fallthrough_offset]
                if 'IF_TRUE' in last_instr.opname or 'IF_NOT_NONE' in last_instr.opname:
                    block.successors.append((ft_block, EdgeType.COND_FALSE, None))
                else:
                    block.successors.append((ft_block, EdgeType.COND_TRUE, None))
                blocks[ft_block].predecessors.append(block.id)
        
        elif last_instr.opname == 'FOR_ITER':
            # For loop: jump target on exhaustion, fallthrough on next item
            target = last_instr.argval
            if target in offset_to_block:
                target_block = offset_to_block[target]
                block.successors.append((target_block, EdgeType.COND_FALSE, "iterator_exhausted"))
                blocks[target_block].predecessors.append(block.id)
            
            fallthrough_offset = block.end_offset
            if fallthrough_offset in offset_to_block:
                ft_block = offset_to_block[fallthrough_offset]
                block.successors.append((ft_block, EdgeType.COND_TRUE, "iterator_has_next"))
                blocks[ft_block].predecessors.append(block.id)
        
        elif last_instr.opname in ('RAISE_VARARGS', 'RERAISE'):
            # Explicit raise - handled by exception edges
            pass
        
        else:
            # Normal fallthrough
            fallthrough_offset = block.end_offset
            if fallthrough_offset in offset_to_block:
                ft_block = offset_to_block[fallthrough_offset]
                block.successors.append((ft_block, EdgeType.FALLTHROUGH, None))
                blocks[ft_block].predecessors.append(block.id)
        
        # Exception edges: find innermost handler for any raising instruction
        for instr in block.instructions:
            for region in exception_regions:
                if region.contains_offset(instr.offset):
                    handler_offset = region.handler_offset
                    if handler_offset in offset_to_block:
                        handler_block = offset_to_block[handler_offset]
                        # Add exception edge if not already present
                        exc_edge = (handler_block, EdgeType.EXCEPTION, None)
                        if exc_edge not in block.successors:
                            block.successors.append(exc_edge)
                            if block.id not in blocks[handler_block].predecessors:
                                blocks[handler_block].predecessors.append(block.id)
                        block.exception_handler = handler_block
                    break  # Only innermost handler matters


def _analyze_variables(blocks: Dict[int, BasicBlock]):
    """Analyze variable loads and stores in each block."""
    
    load_ops = {'LOAD_FAST', 'LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_DEREF', 'LOAD_CLASSDEREF'}
    store_ops = {'STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL', 'STORE_DEREF'}
    
    for block in blocks.values():
        for instr in block.instructions:
            if instr.opname in load_ops:
                if instr.argval and isinstance(instr.argval, str):
                    block.loads.add(instr.argval)
            elif instr.opname in store_ops:
                if instr.argval and isinstance(instr.argval, str):
                    block.stores.add(instr.argval)


def _compute_dominance(cfg: ControlFlowGraph):
    """
    Compute dominance tree using iterative dataflow.
    
    Algorithm: standard iterative dominance computation
    - dom[entry] = {entry}
    - dom[n] = {n} ∪ (∩ dom[p] for p in predecessors of n)
    """
    blocks = cfg.blocks
    entry = cfg.entry_block
    
    # Initialize: dom[entry] = {entry}, dom[n] = all blocks for n != entry
    all_blocks = set(blocks.keys())
    cfg.dominators = {}
    cfg.dominators[entry] = {entry}
    
    for bid in blocks:
        if bid != entry:
            cfg.dominators[bid] = all_blocks.copy()
    
    # Iterate until fixed point
    changed = True
    while changed:
        changed = False
        for bid in blocks:
            if bid == entry:
                continue
            
            block = blocks[bid]
            if not block.predecessors:
                continue
            
            # New dom set = intersection of predecessor doms, plus self
            pred_doms = [cfg.dominators[p] for p in block.predecessors if p in cfg.dominators]
            if pred_doms:
                new_dom = pred_doms[0].copy()
                for pd in pred_doms[1:]:
                    new_dom &= pd
                new_dom.add(bid)
                
                if new_dom != cfg.dominators[bid]:
                    cfg.dominators[bid] = new_dom
                    changed = True
    
    # Compute immediate dominators
    for bid in blocks:
        if bid == entry:
            continue
        
        doms = cfg.dominators.get(bid, set())
        strict_doms = doms - {bid}
        
        # idom is the unique dominator that doesn't dominate any other strict dominator
        for candidate in strict_doms:
            is_idom = True
            for other in strict_doms:
                if other != candidate and candidate in cfg.dominators.get(other, set()):
                    is_idom = False
                    break
            if is_idom:
                cfg.immediate_dominator[bid] = candidate
                break


def _detect_loops(cfg: ControlFlowGraph):
    """
    Detect loops by finding back edges and loop headers.
    
    A back edge is an edge n → h where h dominates n.
    The target h is a loop header.
    """
    for block in cfg.blocks.values():
        for succ_id, edge_type, _ in block.successors:
            # Check if this is a back edge
            if cfg.is_dominated_by(block.id, succ_id):
                cfg.back_edges.append((block.id, succ_id))
                cfg.loop_headers.add(succ_id)


# ============================================================================
# Guard Analysis
# ============================================================================

@dataclass
class GuardFact:
    """
    A guard fact established at a program point.
    
    Corresponds to guard variables in barrier-certificate-theory.tex §7:
    - g_nonnull(v): v is not None
    - g_type(v, T): isinstance(v, T)
    - g_bounds(seq, i): 0 <= i < len(seq)
    - g_div(d): d != 0
    - g_catch(E): exception E will be caught
    """
    guard_type: str  # "nonnull", "type", "bounds", "div", "catch"
    variable: str
    extra: Optional[str] = None  # type for g_type, exception class for g_catch
    established_at: int = 0  # block ID where guard was established
    condition: Optional[str] = None  # The condition that established this guard
    
    def __hash__(self):
        return hash((self.guard_type, self.variable, self.extra))
    
    def __eq__(self, other):
        if not isinstance(other, GuardFact):
            return False
        return (self.guard_type == other.guard_type and 
                self.variable == other.variable and
                self.extra == other.extra)


class GuardAnalyzer:
    """
    Analyze guard establishment and propagation.
    
    Uses dominance information to determine which guards are
    established at each program point.
    """
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        # Maps block_id -> set of GuardFacts established by that block
        self.block_establishes: Dict[int, Set[GuardFact]] = {}
        # Maps block_id -> set of GuardFacts valid at entry to that block
        self.block_guards: Dict[int, Set[GuardFact]] = {}
        
    def analyze(self) -> Dict[int, Set[GuardFact]]:
        """
        Perform guard analysis.
        
        Returns mapping from block_id to guards valid at that block.
        """
        # Step 1: Identify guard-establishing patterns in each block
        self._find_guard_establishments()
        
        # Step 2: Propagate guards using dominance
        self._propagate_guards()
        
        return self.block_guards
    
    def _find_guard_establishments(self):
        """Find guard checks in each block."""
        
        for block in self.cfg.blocks.values():
            guards = set()
            
            for i, instr in enumerate(block.instructions):
                # Pattern: isinstance(v, T) followed by conditional jump
                # LOAD_GLOBAL isinstance
                # LOAD_FAST v
                # LOAD_GLOBAL T
                # CALL 2
                # POP_JUMP_IF_FALSE/TRUE
                if instr.opname == 'CALL' and i >= 2:
                    # Look back for isinstance pattern
                    prev_instrs = block.instructions[max(0, i-4):i]
                    isinstance_guard = self._check_isinstance_pattern(prev_instrs, block)
                    if isinstance_guard:
                        guards.add(isinstance_guard)
                
                # Pattern: if v is not None / if v is None
                # LOAD_FAST v
                # LOAD_CONST None
                # IS_OP 0/1
                # POP_JUMP_IF_FALSE/TRUE
                if instr.opname == 'IS_OP' and i >= 2:
                    none_guard = self._check_none_pattern(block.instructions[:i+2], block)
                    if none_guard:
                        guards.add(none_guard)

                # Pattern (Python 3.14+ specialized): if v is not None / if v is None
                # LOAD_FAST(_BORROW) v
                # POP_JUMP_IF_NONE / POP_JUMP_IF_NOT_NONE
                if instr.opname in (
                    'POP_JUMP_IF_NONE',
                    'POP_JUMP_IF_NOT_NONE',
                    'POP_JUMP_FORWARD_IF_NONE',
                    'POP_JUMP_FORWARD_IF_NOT_NONE',
                ):
                    if i >= 1 and block.instructions[i - 1].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        var_name = block.instructions[i - 1].argval
                        if var_name:
                            # POP_JUMP_IF_NONE: fallthrough implies nonnull
                            # POP_JUMP_IF_NOT_NONE: jump-taken implies nonnull
                            cond = (
                                f"{var_name} is not None"
                                if instr.opname.endswith('_IF_NONE')
                                else f"{var_name} is not None (jump-taken)"
                            )
                            guards.add(
                                GuardFact(
                                    guard_type="nonnull",
                                    variable=var_name,
                                    established_at=block.id,
                                    condition=cond,
                                )
                            )
                
                # Pattern: if v (truthiness check)
                # LOAD_FAST v
                # POP_JUMP_IF_FALSE
                if instr.opname in ('POP_JUMP_IF_FALSE', 'POP_JUMP_FORWARD_IF_FALSE'):
                    if i >= 1 and block.instructions[i-1].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        var_name = block.instructions[i-1].argval
                        if var_name:
                            # Truthiness check establishes nonnull on true branch
                            guard = GuardFact(
                                guard_type="nonnull",
                                variable=var_name,
                                established_at=block.id,
                                condition=f"truthiness check on {var_name}"
                            )
                            guards.add(guard)
                
                # Pattern: x != 0 or 0 != x before division
                if instr.opname == 'COMPARE_OP' and instr.argval == '!=' and i >= 2:
                    div_guard = self._check_div_guard_pattern(block.instructions[:i+1], block)
                    if div_guard:
                        guards.add(div_guard)
            
            self.block_establishes[block.id] = guards
    
    def _check_isinstance_pattern(
        self, 
        prev_instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """Check for isinstance call pattern."""
        # Look for: LOAD_GLOBAL 'isinstance', LOAD_* var, LOAD_* type
        for i, instr in enumerate(prev_instrs):
            if (instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN') and 
                instr.argval == 'isinstance'):
                # Next should be variable load
                if i + 1 < len(prev_instrs):
                    var_instr = prev_instrs[i + 1]
                    if var_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        var_name = var_instr.argval
                        # Next should be type load
                        if i + 2 < len(prev_instrs):
                            type_instr = prev_instrs[i + 2]
                            if type_instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                                type_name = type_instr.argval
                                return GuardFact(
                                    guard_type="type",
                                    variable=var_name,
                                    extra=type_name,
                                    established_at=block.id,
                                    condition=f"isinstance({var_name}, {type_name})"
                                )
        return None
    
    def _check_none_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """Check for 'is None' / 'is not None' pattern."""
        for i, instr in enumerate(instrs):
            if instr.opname == 'IS_OP':
                # IS_OP 0 = 'is', IS_OP 1 = 'is not'
                is_not = instr.arg == 1
                
                # Look back for LOAD_* v, LOAD_CONST None
                if i >= 2:
                    load_instr = instrs[i - 2]
                    const_instr = instrs[i - 1]
                    
                    if (load_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME') and
                        const_instr.opname == 'LOAD_CONST' and 
                        const_instr.argval is None):
                        var_name = load_instr.argval
                        if var_name:
                            # 'is not None' establishes nonnull on true branch
                            # 'is None' establishes nonnull on false branch
                            return GuardFact(
                                guard_type="nonnull",
                                variable=var_name,
                                established_at=block.id,
                                condition=f"{var_name} is not None" if is_not else f"{var_name} is None (false branch)"
                            )
        return None
    
    def _check_div_guard_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """Check for division guard pattern (x != 0)."""
        for i, instr in enumerate(instrs):
            if instr.opname == 'COMPARE_OP' and instr.argval == '!=':
                if i >= 2:
                    left = instrs[i - 2]
                    right = instrs[i - 1]
                    
                    # Pattern: var != 0 or 0 != var
                    if left.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME') and right.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and right.argval == 0:
                        return GuardFact(
                            guard_type="div",
                            variable=left.argval,
                            established_at=block.id,
                            condition=f"{left.argval} != 0"
                        )
                    if right.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME') and left.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and left.argval == 0:
                        return GuardFact(
                            guard_type="div",
                            variable=right.argval,
                            established_at=block.id,
                            condition=f"0 != {right.argval}"
                        )
        return None
    
    def _propagate_guards(self):
        """
        Propagate guards using dominance.
        
        A guard is valid at block B if:
        1. The guard-establishing block dominates B, AND
        2. The guard was established on the path taken to reach B
        """
        # For each block, collect guards from all dominating blocks
        for block_id in self.cfg.blocks:
            valid_guards = set()
            
            # Get all blocks that dominate this one
            dominators = self.cfg.dominators.get(block_id, set())
            
            for dom_id in dominators:
                # Add guards established by this dominator
                established = self.block_establishes.get(dom_id, set())
                
                for guard in established:
                    # Check if this guard is on the path to block_id
                    # For now, conservatively include all dominating guards
                    # TODO: refine with edge-sensitive analysis
                    valid_guards.add(guard)
            
            self.block_guards[block_id] = valid_guards
    
    def get_guards_at_offset(self, offset: int) -> Set[GuardFact]:
        """Get guards valid at a specific instruction offset."""
        block = self.cfg.get_block_for_offset(offset)
        if block:
            return self.block_guards.get(block.id, set())
        return set()
    
    def has_guard(self, offset: int, guard_type: str, variable: str) -> bool:
        """Check if a specific guard is established at an offset."""
        guards = self.get_guards_at_offset(offset)
        for g in guards:
            if g.guard_type == guard_type and g.variable == variable:
                return True
        return False


# ============================================================================
# WillCatchAt Predicate
# ============================================================================

class ExceptionCatchAnalyzer:
    """
    Analyzes exception catching behavior.
    
    Implements the WillCatchAt(pc, exc) predicate from barrier-certificate-theory.tex §9.7.
    """
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
    
    def will_catch_at(self, offset: int, exception_type: str) -> bool:
        """
        Check if an exception of given type will be caught at this offset.
        
        This is an intraprocedural approximation: we check if there's a handler
        in the exception table that covers this offset.
        """
        handler = self.cfg.get_exception_handler(offset)
        if handler is None:
            return False
        
        # Check if handler catches this exception type
        # If exception_types is empty, it's a catch-all
        if not handler.exception_types:
            return True
        
        # Check if exception_type is in the caught types
        # This requires knowing the exception hierarchy
        # For now, exact match or catch-all
        return exception_type in handler.exception_types
    
    def get_handler_at(self, offset: int) -> Optional[int]:
        """Get handler offset for exceptions at this offset."""
        handler = self.cfg.get_exception_handler(offset)
        if handler:
            return handler.handler_offset
        return None
    
    def is_in_try_block(self, offset: int) -> bool:
        """Check if offset is within any try block."""
        return self.cfg.get_exception_handler(offset) is not None


# ============================================================================
# Convenience Functions
# ============================================================================

def analyze_guards(code: types.CodeType) -> Tuple[ControlFlowGraph, Dict[int, Set[GuardFact]]]:
    """
    Perform complete guard analysis on a code object.
    
    Returns:
        (cfg, guard_map) where guard_map maps block_id -> valid guards
    """
    cfg = build_cfg(code)
    analyzer = GuardAnalyzer(cfg)
    guards = analyzer.analyze()
    return cfg, guards


def print_cfg(cfg: ControlFlowGraph, show_guards: bool = True):
    """Print CFG for debugging."""
    print(f"CFG for {cfg.code.co_name}")
    print(f"Entry: block {cfg.entry_block}")
    print(f"Exits: {cfg.exit_blocks}")
    print(f"Loop headers: {cfg.loop_headers}")
    print()
    
    guard_analyzer = None
    if show_guards:
        guard_analyzer = GuardAnalyzer(cfg)
        guard_analyzer.analyze()
    
    for bid, block in sorted(cfg.blocks.items()):
        print(f"Block {bid}:")
        print(f"  Offsets: {block.start_offset} - {block.end_offset}")
        print(f"  Instructions:")
        for instr in block.instructions:
            print(f"    {instr.offset:4d}: {instr.opname} {instr.argrepr}")
        
        print(f"  Successors: {[(s, e.name) for s, e, _ in block.successors]}")
        print(f"  Predecessors: {block.predecessors}")
        
        if block.exception_handler is not None:
            print(f"  Exception handler: block {block.exception_handler}")
        
        print(f"  Loads: {block.loads}")
        print(f"  Stores: {block.stores}")
        
        # Show dominators
        doms = cfg.dominators.get(bid, set())
        print(f"  Dominated by: {sorted(doms)}")
        
        if guard_analyzer and bid in guard_analyzer.block_guards:
            guards = guard_analyzer.block_guards[bid]
            if guards:
                print(f"  Guards valid: {[str(g) for g in guards]}")
        
        print()
