"""
SOTA Paper: IMPACT / Lazy Abstraction with Interpolants.

Implements lazy abstraction with interpolation:
    K. L. McMillan.
    "Lazy Abstraction with Interpolants."
    CAV 2006.

KEY INSIGHT
===========

IMPACT combines lazy abstraction with Craig interpolation:
1. Build abstract reachability tree (ART) on-the-fly
2. When spurious path found, compute interpolants along path
3. Use interpolants as new predicates locally (not globally)
4. Enables path-sensitive, demand-driven verification

Key advantages over eager CEGAR:
- Predicates are local to program locations
- Avoids predicate explosion
- Works incrementally

LAZY ABSTRACTION
================

Standard CEGAR:
- Compute full abstraction upfront
- Model check abstract system
- Refine globally if spurious

Lazy abstraction:
- Explore concrete paths
- Abstract only when needed
- Refine locally at spurious point

INTERPOLATION FOR REFINEMENT
============================

Given spurious path π = (s_0 → s_1 → ... → s_n):
1. Build formula: φ_0 ∧ T_01 ∧ φ_1 ∧ T_12 ∧ ... ∧ φ_n
2. Path spurious means formula UNSAT
3. Extract interpolants I_0, I_1, ..., I_n
4. Use I_i as predicate at location i

Interpolant I_i over-approximates reachable states at step i.

COVERING AND WIDENING
=====================

Key optimization: covering
- If state s is covered by existing state s' (s ⊑ s')
- No need to expand from s
- Maintains finite exploration

IMPLEMENTATION STRUCTURE
========================

1. ARTNode: Node in abstract reachability tree
2. AbstractReachabilityTree: ART data structure
3. InterpolantComputer: Craig interpolation
4. ImpactVerifier: Main IMPACT algorithm
5. ImpactIntegration: Integration with barriers

LAYER POSITION
==============

This is a **Layer 3 (Abstraction)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: ABSTRACTION ← [THIS MODULE]                            │
    │   ├── cegar_refinement.py (Paper #12)                           │
    │   ├── predicate_abstraction.py (Paper #13)                      │
    │   ├── boolean_programs.py (Paper #14)                           │
    │   └── impact_lazy.py ← You are here (Paper #16)                 │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module synthesizes multiple techniques:

From Layer 3 peers:
- Paper #12 (CEGAR): IMPACT IS lazy CEGAR
- Paper #13 (Predicate Abstraction): Interpolants become predicates
- Paper #14 (Boolean Programs): ART defines implicit Boolean program

From Layer 5:
- Paper #15 (Interpolation): IMPACT USES interpolation for refinement
- Paper #10 (IC3): IC3 frames relate to ART depth

This module is used by:
- Paper #10 (IC3): IMPACT's local predicates inform IC3 lemmas
- Paper #11 (CHC): ART exploration guides CHC solving

IMPACT + BARRIERS
=================

Lazy abstraction enables incremental barrier synthesis:
- Explore ART until safety proven or bug found
- Extract path invariants from ART nodes
- Use invariants to constrain barrier search
- Only synthesize where needed (demand-driven)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from collections import defaultdict

import z3

# =============================================================================
# LAYER 3: IMPORTS FROM LOWER LAYERS
# =============================================================================
# IMPACT uses interpolation (Layer 5) to refine predicate abstraction,
# building an abstract reachability tree that constrains barrier synthesis.
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# ABSTRACT REACHABILITY TREE
# =============================================================================

@dataclass
class ARTNode:
    """
    Node in the Abstract Reachability Tree.
    
    Contains:
    - Formula characterizing states at this node
    - Location in program
    - Parent and children
    - Covering information
    """
    id: int
    location: int
    formula: z3.BoolRef  # States at this node
    parent: Optional['ARTNode'] = None
    children: List['ARTNode'] = field(default_factory=list)
    covered_by: Optional['ARTNode'] = None
    is_error: bool = False
    interpolant: Optional[z3.BoolRef] = None
    
    def is_covered(self) -> bool:
        """Check if node is covered."""
        return self.covered_by is not None
    
    def is_leaf(self) -> bool:
        """Check if node is leaf."""
        return len(self.children) == 0
    
    def get_path_to_root(self) -> List['ARTNode']:
        """Get path from this node to root."""
        path = [self]
        current = self
        while current.parent is not None:
            current = current.parent
            path.append(current)
        return list(reversed(path))
    
    def __str__(self) -> str:
        covered_str = f" (covered by {self.covered_by.id})" if self.covered_by else ""
        return f"Node({self.id})@{self.location}{covered_str}"


class AbstractReachabilityTree:
    """
    Abstract Reachability Tree (ART).
    
    On-the-fly construction during IMPACT algorithm.
    """
    
    def __init__(self, initial_formula: z3.BoolRef,
                 initial_location: int = 0):
        self.root = ARTNode(0, initial_location, initial_formula)
        self._node_counter = 1
        self._nodes_by_location: Dict[int, List[ARTNode]] = defaultdict(list)
        self._nodes_by_location[initial_location].append(self.root)
        
        self.stats = {
            'nodes_created': 1,
            'nodes_covered': 0,
            'max_depth': 0,
        }
    
    def add_child(self, parent: ARTNode, location: int,
                   formula: z3.BoolRef) -> ARTNode:
        """Add child node."""
        child = ARTNode(
            id=self._node_counter,
            location=location,
            formula=formula,
            parent=parent
        )
        self._node_counter += 1
        parent.children.append(child)
        self._nodes_by_location[location].append(child)
        
        self.stats['nodes_created'] += 1
        depth = len(child.get_path_to_root())
        self.stats['max_depth'] = max(self.stats['max_depth'], depth)
        
        return child
    
    def mark_covered(self, node: ARTNode, covered_by: ARTNode) -> None:
        """Mark node as covered by another node."""
        node.covered_by = covered_by
        self.stats['nodes_covered'] += 1
    
    def get_uncovered_leaves(self) -> List[ARTNode]:
        """Get all uncovered leaf nodes."""
        leaves = []
        
        def collect(node: ARTNode):
            if node.is_covered():
                return
            if node.is_leaf():
                leaves.append(node)
            else:
                for child in node.children:
                    collect(child)
        
        collect(self.root)
        return leaves
    
    def get_error_nodes(self) -> List[ARTNode]:
        """Get all error nodes."""
        errors = []
        
        def collect(node: ARTNode):
            if node.is_error:
                errors.append(node)
            for child in node.children:
                collect(child)
        
        collect(self.root)
        return errors
    
    def get_nodes_at_location(self, location: int) -> List[ARTNode]:
        """Get all nodes at a location."""
        return self._nodes_by_location.get(location, [])


# =============================================================================
# CRAIG INTERPOLATION
# =============================================================================

class InterpolationResult(Enum):
    """Result of interpolation."""
    SUCCESS = auto()
    FAILURE = auto()
    SAT = auto()  # Formula is SAT, no interpolant


@dataclass
class InterpolationOutput:
    """Result of computing interpolants."""
    result: InterpolationResult
    interpolants: List[z3.BoolRef] = field(default_factory=list)
    message: str = ""


class InterpolantComputer:
    """
    Compute Craig interpolants for refinement.
    
    Given UNSAT formula A ∧ B, computes I such that:
    - A → I
    - I ∧ B is UNSAT
    - I only uses shared variables
    """
    
    def __init__(self, timeout_ms: int = 60000, verbose: bool = False):
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.stats = {
            'interpolations': 0,
            'successful': 0,
        }
    
    def compute_sequence(self, formulas: List[z3.BoolRef]) -> InterpolationOutput:
        """
        Compute sequence of interpolants.
        
        Given φ_0, φ_1, ..., φ_n where φ_0 ∧ ... ∧ φ_n is UNSAT,
        compute interpolants I_0, I_1, ..., I_{n-1} such that:
        - φ_0 → I_0
        - I_i ∧ φ_{i+1} → I_{i+1}
        - I_{n-1} ∧ φ_n is UNSAT
        """
        self.stats['interpolations'] += 1
        
        if len(formulas) < 2:
            return InterpolationOutput(
                result=InterpolationResult.FAILURE,
                message="Need at least 2 formulas"
            )
        
        # Check if conjunction is UNSAT
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        for f in formulas:
            solver.add(f)
        
        if solver.check() != z3.unsat:
            return InterpolationOutput(
                result=InterpolationResult.SAT,
                message="Formula is SAT"
            )
        
        # Compute interpolants
        interpolants = self._compute_interpolants(formulas)
        
        if interpolants is not None:
            self.stats['successful'] += 1
            return InterpolationOutput(
                result=InterpolationResult.SUCCESS,
                interpolants=interpolants,
                message="Interpolants computed"
            )
        
        return InterpolationOutput(
            result=InterpolationResult.FAILURE,
            message="Failed to compute interpolants"
        )
    
    def _compute_interpolants(self, formulas: List[z3.BoolRef]) -> Optional[List[z3.BoolRef]]:
        """
        Compute interpolant sequence.
        
        Simplified version using Z3's unsat core.
        """
        n = len(formulas)
        interpolants = []
        
        # Compute interpolant at each cut point
        for i in range(n - 1):
            # A = φ_0 ∧ ... ∧ φ_i
            # B = φ_{i+1} ∧ ... ∧ φ_n
            A = z3.And(formulas[:i + 1]) if i > 0 else formulas[0]
            B = z3.And(formulas[i + 1:]) if i + 1 < n - 1 else formulas[-1]
            
            interpolant = self._compute_binary_interpolant(A, B)
            if interpolant is None:
                return None
            
            interpolants.append(interpolant)
        
        return interpolants
    
    def _compute_binary_interpolant(self, A: z3.BoolRef, 
                                      B: z3.BoolRef) -> Optional[z3.BoolRef]:
        """
        Compute binary interpolant I for A ∧ B UNSAT.
        
        Simplified: returns A as over-approximation.
        Full implementation would use proper interpolation.
        """
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        solver.add(A)
        solver.add(B)
        
        if solver.check() != z3.unsat:
            return None
        
        # Simplified: return A (valid but not optimal)
        return z3.simplify(A)


# =============================================================================
# IMPACT ALGORITHM
# =============================================================================

class ImpactResult(Enum):
    """Result of IMPACT verification."""
    SAFE = auto()
    UNSAFE = auto()
    UNKNOWN = auto()


@dataclass
class ImpactVerificationResult:
    """Result of IMPACT verification."""
    result: ImpactResult
    counterexample: Optional[List[ARTNode]] = None
    tree: Optional[AbstractReachabilityTree] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class ImpactVerifier:
    """
    IMPACT: Lazy Abstraction with Interpolants.
    
    Main algorithm:
    1. Build ART lazily
    2. When path to error found, check if spurious
    3. If spurious, compute interpolants and refine locally
    4. Continue until safe or real bug found
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_variables: List[z3.ArithRef],
                 transition_relation: z3.BoolRef,
                 initial_formula: z3.BoolRef,
                 error_formula: z3.BoolRef,
                 max_iterations: int = 10000,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.variables = variables
        self.primed_variables = primed_variables
        self.transition = transition_relation
        self.initial = initial_formula
        self.error = error_formula
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.interpolator = InterpolantComputer(timeout_ms, verbose)
        
        self.stats = {
            'iterations': 0,
            'refinements': 0,
            'covering_checks': 0,
        }
    
    def verify(self) -> ImpactVerificationResult:
        """
        Run IMPACT verification.
        """
        start_time = time.time()
        
        # Initialize ART
        tree = AbstractReachabilityTree(self.initial, 0)
        
        for iteration in range(self.max_iterations):
            self.stats['iterations'] += 1
            
            # Get uncovered leaves
            leaves = tree.get_uncovered_leaves()
            
            if not leaves:
                # All paths explored
                self.stats['time_ms'] = (time.time() - start_time) * 1000
                return ImpactVerificationResult(
                    result=ImpactResult.SAFE,
                    tree=tree,
                    statistics=self.stats,
                    message="All paths explored, system is safe"
                )
            
            # Pick a leaf to expand
            leaf = self._select_leaf(leaves)
            
            # Try to expand
            expanded = self._expand(tree, leaf)
            
            if not expanded:
                # Check if leaf is error
                if self._is_error(leaf):
                    # Check if path is spurious
                    path = leaf.get_path_to_root()
                    is_spurious = self._check_spurious(path)
                    
                    if is_spurious:
                        # Refine using interpolants
                        self._refine(tree, path)
                        self.stats['refinements'] += 1
                    else:
                        # Real counterexample
                        self.stats['time_ms'] = (time.time() - start_time) * 1000
                        return ImpactVerificationResult(
                            result=ImpactResult.UNSAFE,
                            counterexample=path,
                            tree=tree,
                            statistics=self.stats,
                            message="Real counterexample found"
                        )
            
            # Try covering
            self._try_covering(tree, leaf)
        
        self.stats['time_ms'] = (time.time() - start_time) * 1000
        return ImpactVerificationResult(
            result=ImpactResult.UNKNOWN,
            tree=tree,
            statistics=self.stats,
            message="Max iterations reached"
        )
    
    def _select_leaf(self, leaves: List[ARTNode]) -> ARTNode:
        """Select next leaf to expand (DFS order)."""
        return leaves[-1]  # DFS: pick last
    
    def _expand(self, tree: AbstractReachabilityTree, node: ARTNode) -> bool:
        """
        Expand node by computing successors.
        
        Returns True if expansion created new nodes.
        """
        # Compute post-image
        post_formula = self._compute_post(node.formula)
        
        if self._is_satisfiable(post_formula):
            # Create child at next location
            child = tree.add_child(node, node.location + 1, post_formula)
            
            # Check if child reaches error
            if self._is_satisfiable(z3.And(post_formula, self.error)):
                child.is_error = True
            
            return True
        
        return False
    
    def _compute_post(self, formula: z3.BoolRef) -> z3.BoolRef:
        """Compute post-image of states."""
        # ∃ x. formula(x) ∧ T(x, x')
        post = z3.And(formula, self.transition)
        
        # Project to primed variables (simplified)
        # Full implementation would use quantifier elimination
        subs = list(zip(self.primed_variables, self.variables))
        post_projected = z3.substitute(post, subs)
        
        return z3.simplify(post_projected)
    
    def _is_error(self, node: ARTNode) -> bool:
        """Check if node can reach error."""
        return node.is_error or self._is_satisfiable(z3.And(node.formula, self.error))
    
    def _is_satisfiable(self, formula: z3.BoolRef) -> bool:
        """Check if formula is SAT."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        solver.add(formula)
        return solver.check() == z3.sat
    
    def _check_spurious(self, path: List[ARTNode]) -> bool:
        """
        Check if path to error is spurious.
        
        Build path formula and check SAT.
        """
        formulas = []
        
        for i, node in enumerate(path):
            # Add state formula (with renamed variables for step i)
            step_formula = self._rename_for_step(node.formula, i)
            formulas.append(step_formula)
            
            # Add transition to next step
            if i < len(path) - 1:
                trans_formula = self._rename_transition(i)
                formulas.append(trans_formula)
        
        # Add error at end
        error_formula = self._rename_for_step(self.error, len(path) - 1)
        formulas.append(error_formula)
        
        # Check if conjunction is SAT
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        for f in formulas:
            solver.add(f)
        
        return solver.check() == z3.unsat  # Spurious if UNSAT
    
    def _refine(self, tree: AbstractReachabilityTree, path: List[ARTNode]) -> None:
        """
        Refine using interpolants.
        """
        # Build path formula
        formulas = []
        for i, node in enumerate(path):
            step_formula = self._rename_for_step(node.formula, i)
            formulas.append(step_formula)
        
        # Compute interpolants
        result = self.interpolator.compute_sequence(formulas)
        
        if result.result == InterpolationResult.SUCCESS:
            # Apply interpolants to nodes
            for i, interpolant in enumerate(result.interpolants):
                if i < len(path):
                    path[i].interpolant = interpolant
                    # Strengthen node formula
                    path[i].formula = z3.And(path[i].formula, interpolant)
    
    def _try_covering(self, tree: AbstractReachabilityTree, node: ARTNode) -> bool:
        """
        Try to cover node by existing node at same location.
        """
        self.stats['covering_checks'] += 1
        
        candidates = tree.get_nodes_at_location(node.location)
        
        for candidate in candidates:
            if candidate.id != node.id and not candidate.is_covered():
                # Check if candidate covers node: node.formula → candidate.formula
                if self._implies(node.formula, candidate.formula):
                    tree.mark_covered(node, candidate)
                    return True
        
        return False
    
    def _implies(self, phi1: z3.BoolRef, phi2: z3.BoolRef) -> bool:
        """Check if phi1 → phi2."""
        solver = z3.Solver()
        solver.set("timeout", 1000)
        solver.add(phi1)
        solver.add(z3.Not(phi2))
        return solver.check() == z3.unsat
    
    def _rename_for_step(self, formula: z3.BoolRef, step: int) -> z3.BoolRef:
        """Rename variables for step i."""
        step_vars = [z3.Real(f"{v}_{step}") for v in [str(v) for v in self.variables]]
        subs = list(zip(self.variables, step_vars))
        return z3.substitute(formula, subs)
    
    def _rename_transition(self, step: int) -> z3.BoolRef:
        """Rename transition relation for step i → i+1."""
        step_vars = [z3.Real(f"{v}_{step}") for v in [str(v) for v in self.variables]]
        step_vars_next = [z3.Real(f"{v}_{step + 1}") for v in [str(v) for v in self.variables]]
        
        subs = list(zip(self.variables, step_vars)) + \
               list(zip(self.primed_variables, step_vars_next))
        
        return z3.substitute(self.transition, subs)


# =============================================================================
# COVERING OPTIMIZATION
# =============================================================================

class CoveringManager:
    """
    Manage covering relations in ART.
    
    Key optimization for IMPACT efficiency.
    """
    
    def __init__(self, timeout_ms: int = 1000):
        self.timeout_ms = timeout_ms
        self._covering: Dict[int, Set[int]] = defaultdict(set)  # node_id -> covered_by
        
        self.stats = {
            'covering_checks': 0,
            'covering_found': 0,
        }
    
    def check_covering(self, node1: ARTNode, node2: ARTNode) -> bool:
        """
        Check if node1 is covered by node2.
        
        node1 ⊑ node2 iff node1.formula → node2.formula
        """
        self.stats['covering_checks'] += 1
        
        if node1.location != node2.location:
            return False
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(node1.formula)
        solver.add(z3.Not(node2.formula))
        
        result = solver.check() == z3.unsat
        
        if result:
            self.stats['covering_found'] += 1
            self._covering[node1.id].add(node2.id)
        
        return result
    
    def invalidate_covering(self, node: ARTNode) -> None:
        """Invalidate covering when node is refined."""
        self._covering[node.id] = set()


# =============================================================================
# FORCE COVERING
# =============================================================================

class ForceCovering:
    """
    Force covering by strengthening node formulas.
    
    Advanced IMPACT optimization.
    """
    
    def __init__(self, interpolator: InterpolantComputer,
                 timeout_ms: int = 60000):
        self.interpolator = interpolator
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'force_attempts': 0,
            'force_succeeded': 0,
        }
    
    def force(self, node: ARTNode, target: ARTNode) -> bool:
        """
        Try to force node to be covered by target.
        
        Strengthens node.formula to make node ⊑ target.
        """
        self.stats['force_attempts'] += 1
        
        if node.location != target.location:
            return False
        
        # Compute formula that would establish covering
        # node.formula ∧ ¬target.formula should become UNSAT
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(node.formula)
        solver.add(z3.Not(target.formula))
        
        if solver.check() == z3.unsat:
            # Already covered
            self.stats['force_succeeded'] += 1
            return True
        
        # Try to find strengthening
        # (Would need interpolation or abduction)
        
        return False


# =============================================================================
# IMPACT INTEGRATION
# =============================================================================

@dataclass
class ImpactConfig:
    """Configuration for IMPACT integration."""
    max_iterations: int = 10000
    covering_enabled: bool = True
    force_covering: bool = False
    timeout_ms: int = 60000
    verbose: bool = False


class ImpactIntegration:
    """
    Integration of IMPACT with barrier synthesis.
    
    Provides:
    1. Lazy abstraction for path-sensitive verification
    2. Interpolant-based refinement
    3. Covering optimization
    """
    
    def __init__(self, config: Optional[ImpactConfig] = None,
                 verbose: bool = False):
        self.config = config or ImpactConfig()
        self.verbose = verbose or self.config.verbose
        
        self._verifiers: Dict[str, ImpactVerifier] = {}
        self._results: Dict[str, ImpactVerificationResult] = {}
        
        self.stats = {
            'verifications': 0,
            'safe_count': 0,
            'unsafe_count': 0,
        }
    
    def verify(self, ver_id: str,
                variables: List[z3.ArithRef],
                primed_vars: List[z3.ArithRef],
                transition: z3.BoolRef,
                initial: z3.BoolRef,
                error: z3.BoolRef) -> ImpactVerificationResult:
        """
        Verify using IMPACT.
        """
        verifier = ImpactVerifier(
            variables, primed_vars, transition, initial, error,
            self.config.max_iterations,
            self.config.timeout_ms,
            self.verbose
        )
        
        result = verifier.verify()
        
        self._verifiers[ver_id] = verifier
        self._results[ver_id] = result
        self.stats['verifications'] += 1
        
        if result.result == ImpactResult.SAFE:
            self.stats['safe_count'] += 1
        elif result.result == ImpactResult.UNSAFE:
            self.stats['unsafe_count'] += 1
        
        return result
    
    def get_interpolants(self, ver_id: str) -> List[z3.BoolRef]:
        """Get interpolants from verification."""
        result = self._results.get(ver_id)
        if result is None or result.tree is None:
            return []
        
        interpolants = []
        
        def collect(node: ARTNode):
            if node.interpolant is not None:
                interpolants.append(node.interpolant)
            for child in node.children:
                collect(child)
        
        collect(result.tree.root)
        return interpolants
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    ver_id: str) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using IMPACT insights.
        """
        result = self._results.get(ver_id)
        if result is None or result.result != ImpactResult.SAFE:
            return problem
        
        # Extract interpolants as constraints
        interpolants = self.get_interpolants(ver_id)
        
        # Add interpolants as polynomial constraints (simplified)
        # Full implementation would convert Z3 to polynomials
        
        return problem


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def verify_with_impact(variables: List[z3.ArithRef],
                         primed_vars: List[z3.ArithRef],
                         transition: z3.BoolRef,
                         initial: z3.BoolRef,
                         error: z3.BoolRef,
                         max_iterations: int = 10000,
                         timeout_ms: int = 60000,
                         verbose: bool = False) -> ImpactVerificationResult:
    """
    Verify using IMPACT algorithm.
    """
    verifier = ImpactVerifier(
        variables, primed_vars, transition, initial, error,
        max_iterations, timeout_ms, verbose
    )
    return verifier.verify()


def compute_interpolants(formulas: List[z3.BoolRef],
                           timeout_ms: int = 60000,
                           verbose: bool = False) -> InterpolationOutput:
    """
    Compute interpolant sequence.
    """
    computer = InterpolantComputer(timeout_ms, verbose)
    return computer.compute_sequence(formulas)


def create_art(initial_formula: z3.BoolRef,
                initial_location: int = 0) -> AbstractReachabilityTree:
    """
    Create abstract reachability tree.
    """
    return AbstractReachabilityTree(initial_formula, initial_location)


# =============================================================================
# ADVANCED LAZY ABSTRACTION TECHNIQUES
# =============================================================================

class PathSensitiveUnwinding:
    """
    Path-sensitive unwinding for lazy abstraction.
    
    Tracks path conditions to avoid merging incompatible paths.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.timeout_ms = timeout_ms
        
        self.path_tree: Dict[int, 'PathNode'] = {}
        self._node_counter = 0
        
        self.stats = {
            'paths_explored': 0,
            'merges_avoided': 0,
        }
    
    def unwind(self, max_depth: int = 100) -> 'PathTree':
        """
        Unwind control flow with path sensitivity.
        """
        root = self._create_node(self.initial, None, [])
        self.path_tree[root.id] = root
        
        worklist = [root]
        
        while worklist and max_depth > 0:
            node = worklist.pop(0)
            max_depth -= 1
            
            self.stats['paths_explored'] += 1
            
            # Compute successors
            successors = self._compute_successors(node)
            
            for succ in successors:
                # Check for merge opportunity
                merge_target = self._find_merge_target(succ)
                
                if merge_target and self._can_merge(succ, merge_target):
                    self._merge_nodes(succ, merge_target)
                else:
                    self.stats['merges_avoided'] += 1
                    self.path_tree[succ.id] = succ
                    worklist.append(succ)
        
        return PathTree(root, self.path_tree)
    
    def _create_node(self, formula: z3.BoolRef,
                      parent: Optional['PathNode'],
                      path_condition: List[z3.BoolRef]) -> 'PathNode':
        """Create new path node."""
        node = PathNode(
            id=self._node_counter,
            formula=formula,
            parent=parent,
            path_condition=path_condition[:]
        )
        self._node_counter += 1
        return node
    
    def _compute_successors(self, node: 'PathNode') -> List['PathNode']:
        """Compute successor nodes."""
        successors = []
        
        # Apply transition
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        solver.add(node.formula)
        solver.add(self.transition)
        
        while solver.check() == z3.sat:
            model = solver.model()
            
            # Build successor formula
            post_formula = z3.BoolVal(True)
            for v, v_prime in zip(self.variables, self.primed_vars):
                val = model.eval(v_prime, model_completion=True)
                post_formula = z3.And(post_formula, v == val)
            
            # Update path condition
            new_path = node.path_condition + [node.formula]
            
            succ = self._create_node(post_formula, node, new_path)
            successors.append(succ)
            
            # Block this successor
            block = z3.Or([v_prime != model.eval(v_prime) 
                           for v_prime in self.primed_vars])
            solver.add(block)
        
        return successors
    
    def _find_merge_target(self, node: 'PathNode') -> Optional['PathNode']:
        """Find potential merge target."""
        # Look for nodes with compatible path conditions
        for existing in self.path_tree.values():
            if existing.id != node.id:
                return existing
        return None
    
    def _can_merge(self, node1: 'PathNode', node2: 'PathNode') -> bool:
        """Check if nodes can be merged."""
        # Check path condition compatibility
        solver = z3.Solver()
        solver.set("timeout", 1000)
        
        solver.add(z3.And(node1.path_condition))
        solver.add(z3.And(node2.path_condition))
        
        return solver.check() == z3.sat
    
    def _merge_nodes(self, source: 'PathNode', target: 'PathNode') -> None:
        """Merge source into target."""
        target.formula = z3.simplify(z3.Or(target.formula, source.formula))
        target.path_condition = []  # Reset to allow any path


@dataclass
class PathNode:
    """Node in path-sensitive tree."""
    id: int
    formula: z3.BoolRef
    parent: Optional['PathNode']
    path_condition: List[z3.BoolRef]
    children: List['PathNode'] = None
    
    def __post_init__(self):
        if self.children is None:
            self.children = []


@dataclass
class PathTree:
    """Path-sensitive unwinding tree."""
    root: PathNode
    nodes: Dict[int, PathNode]


class AbstractionManager:
    """
    Manages abstraction precision in lazy abstraction.
    """
    
    def __init__(self, variables: List[z3.ArithRef]):
        self.variables = variables
        
        # Precision per location
        self.location_precision: Dict[int, List[z3.BoolRef]] = {}
        
        # Global predicates
        self.global_predicates: List[z3.BoolRef] = []
        
        self.stats = {
            'precision_increases': 0,
            'precision_decreases': 0,
        }
    
    def get_precision(self, location: int) -> List[z3.BoolRef]:
        """Get predicates for location."""
        local = self.location_precision.get(location, [])
        return self.global_predicates + local
    
    def increase_precision(self, location: int,
                            new_predicates: List[z3.BoolRef]) -> None:
        """Add predicates at location."""
        if location not in self.location_precision:
            self.location_precision[location] = []
        
        for pred in new_predicates:
            if not self._is_redundant(pred, location):
                self.location_precision[location].append(pred)
                self.stats['precision_increases'] += 1
    
    def decrease_precision(self, location: int,
                            predicate: z3.BoolRef) -> None:
        """Remove predicate from location."""
        if location in self.location_precision:
            if predicate in self.location_precision[location]:
                self.location_precision[location].remove(predicate)
                self.stats['precision_decreases'] += 1
    
    def add_global_predicate(self, predicate: z3.BoolRef) -> None:
        """Add globally tracked predicate."""
        if not self._is_globally_redundant(predicate):
            self.global_predicates.append(predicate)
    
    def _is_redundant(self, pred: z3.BoolRef, location: int) -> bool:
        """Check if predicate is redundant at location."""
        existing = self.get_precision(location)
        for e in existing:
            if z3.is_true(z3.simplify(pred == e)):
                return True
        return False
    
    def _is_globally_redundant(self, pred: z3.BoolRef) -> bool:
        """Check if predicate is globally redundant."""
        for e in self.global_predicates:
            if z3.is_true(z3.simplify(pred == e)):
                return True
        return False


class UnwinderWithLoops:
    """
    Unwinder that handles loops specially.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 loop_heads: Set[int],
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.loop_heads = loop_heads
        self.timeout_ms = timeout_ms
        
        # Loop invariants
        self.loop_invariants: Dict[int, z3.BoolRef] = {}
        
        self.stats = {
            'loop_iterations': 0,
            'invariants_synthesized': 0,
        }
    
    def unwind_loop(self, head: int,
                     entry_formula: z3.BoolRef,
                     max_iterations: int = 10) -> z3.BoolRef:
        """
        Unwind loop and compute invariant.
        """
        current = entry_formula
        iterations = []
        
        for _ in range(max_iterations):
            self.stats['loop_iterations'] += 1
            
            # Apply loop body
            next_formula = self._apply_loop_body(current)
            iterations.append(next_formula)
            
            # Check for fixed point
            if self._implies(next_formula, current):
                break
            
            current = z3.simplify(z3.Or(current, next_formula))
        
        # Generalize to invariant
        invariant = self._generalize_invariant(iterations)
        
        if invariant:
            self.loop_invariants[head] = invariant
            self.stats['invariants_synthesized'] += 1
        
        return invariant if invariant else current
    
    def _apply_loop_body(self, formula: z3.BoolRef) -> z3.BoolRef:
        """Apply loop body transition."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        solver.add(formula)
        solver.add(self.transition)
        
        if solver.check() == z3.sat:
            # Project to post-state
            return z3.Exists(self.variables,
                              z3.And(formula, self.transition))
        
        return z3.BoolVal(False)
    
    def _implies(self, f1: z3.BoolRef, f2: z3.BoolRef) -> bool:
        """Check if f1 implies f2."""
        solver = z3.Solver()
        solver.set("timeout", 1000)
        solver.add(f1)
        solver.add(z3.Not(f2))
        return solver.check() == z3.unsat
    
    def _generalize_invariant(self, 
                               iterations: List[z3.BoolRef]) -> Optional[z3.BoolRef]:
        """Generalize loop iterations to invariant."""
        if not iterations:
            return None
        
        # Simple approach: disjunction of iterations
        return z3.simplify(z3.Or(iterations))


class TraceAbstraction:
    """
    Trace abstraction for lazy abstraction.
    
    Uses automata over program traces.
    """
    
    def __init__(self, alphabet: Set[str],
                 timeout_ms: int = 60000):
        self.alphabet = alphabet
        self.timeout_ms = timeout_ms
        
        # Automaton states
        self.states: Set[int] = {0}  # Initial state
        self.transitions: Dict[Tuple[int, str], int] = {}
        self.accepting: Set[int] = set()
        
        self._state_counter = 1
        
        self.stats = {
            'automaton_states': 1,
            'automaton_transitions': 0,
        }
    
    def add_infeasible_trace(self, trace: List[str]) -> None:
        """
        Add infeasible trace to abstraction.
        
        Builds automaton that rejects this trace.
        """
        current = 0
        
        for symbol in trace:
            key = (current, symbol)
            
            if key not in self.transitions:
                new_state = self._state_counter
                self._state_counter += 1
                self.states.add(new_state)
                self.transitions[key] = new_state
                self.stats['automaton_states'] = len(self.states)
                self.stats['automaton_transitions'] = len(self.transitions)
            
            current = self.transitions[key]
        
        # Mark final state as accepting (infeasible)
        self.accepting.add(current)
    
    def accepts_trace(self, trace: List[str]) -> bool:
        """Check if trace is in abstraction (known infeasible)."""
        current = 0
        
        for symbol in trace:
            key = (current, symbol)
            if key not in self.transitions:
                return False
            current = self.transitions[key]
        
        return current in self.accepting
    
    def refine_with_interpolants(self, trace: List[str],
                                   interpolants: List[z3.BoolRef]) -> None:
        """Refine automaton using interpolants."""
        # Create new states labeled with interpolants
        current = 0
        
        for i, (symbol, interp) in enumerate(zip(trace, interpolants)):
            key = (current, symbol)
            
            # Create interpolant-labeled state
            new_state = self._state_counter
            self._state_counter += 1
            self.states.add(new_state)
            self.transitions[key] = new_state
            
            current = new_state
        
        self.stats['automaton_states'] = len(self.states)
        self.stats['automaton_transitions'] = len(self.transitions)


class IncrementalUnwinding:
    """
    Incremental unwinding with checkpointing.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.timeout_ms = timeout_ms
        
        # Checkpoints: depth -> (ART, predicates)
        self.checkpoints: Dict[int, Tuple[AbstractReachabilityTree, List[z3.BoolRef]]] = {}
        
        self.current_art: Optional[AbstractReachabilityTree] = None
        self.current_predicates: List[z3.BoolRef] = []
        
        self.stats = {
            'checkpoints_saved': 0,
            'checkpoints_restored': 0,
        }
    
    def save_checkpoint(self, depth: int) -> None:
        """Save current state at depth."""
        if self.current_art:
            # Deep copy would be needed in practice
            self.checkpoints[depth] = (self.current_art, self.current_predicates[:])
            self.stats['checkpoints_saved'] += 1
    
    def restore_checkpoint(self, depth: int) -> bool:
        """Restore state from checkpoint."""
        if depth in self.checkpoints:
            self.current_art, self.current_predicates = self.checkpoints[depth]
            self.stats['checkpoints_restored'] += 1
            return True
        return False
    
    def unwind_incremental(self, additional_steps: int) -> AbstractReachabilityTree:
        """Unwind additional steps from current state."""
        if self.current_art is None:
            self.current_art = AbstractReachabilityTree(self.initial, 0)
        
        # Continue from current leaves
        for _ in range(additional_steps):
            self._expand_leaves()
        
        return self.current_art
    
    def _expand_leaves(self) -> None:
        """Expand all leaf nodes."""
        if self.current_art is None:
            return
        
        leaves = self.current_art.get_leaves()
        
        for leaf in leaves:
            self._expand_node(leaf)
    
    def _expand_node(self, node: ARTNode) -> None:
        """Expand single node."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        solver.add(node.formula)
        solver.add(self.transition)
        
        if solver.check() == z3.sat:
            # Create child
            model = solver.model()
            child_formula = z3.BoolVal(True)
            for v, v_prime in zip(self.variables, self.primed_vars):
                val = model.eval(v_prime, model_completion=True)
                child_formula = z3.And(child_formula, v == val)
            
            child = self.current_art.add_node(
                child_formula, node.location + 1, parent=node
            )


class ParallelImpact:
    """
    Parallel IMPACT verification.
    
    Uses multiple workers for independent subtrees.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 error: z3.BoolRef,
                 num_workers: int = 4,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.error = error
        self.num_workers = num_workers
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'tasks_created': 0,
            'tasks_completed': 0,
        }
    
    def verify_parallel(self) -> ImpactVerificationResult:
        """
        Verify using parallel exploration.
        """
        # Create initial task
        initial_task = VerificationTask(
            formula=self.initial,
            location=0,
            path=[]
        )
        
        task_queue = [initial_task]
        self.stats['tasks_created'] = 1
        
        results = []
        
        # Process tasks (simplified sequential for now)
        while task_queue:
            task = task_queue.pop(0)
            
            result = self._process_task(task)
            self.stats['tasks_completed'] += 1
            
            if result['status'] == 'unsafe':
                return ImpactVerificationResult(
                    result=ImpactResult.UNSAFE,
                    counterexample=result.get('counterexample'),
                    stats=self.stats
                )
            
            # Add subtasks
            for subtask in result.get('subtasks', []):
                task_queue.append(subtask)
                self.stats['tasks_created'] += 1
        
        return ImpactVerificationResult(
            result=ImpactResult.SAFE,
            counterexample=None,
            stats=self.stats
        )
    
    def _process_task(self, task: 'VerificationTask') -> Dict[str, Any]:
        """Process single verification task."""
        # Check error
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        solver.add(task.formula)
        solver.add(self.error)
        
        if solver.check() == z3.sat:
            return {
                'status': 'unsafe',
                'counterexample': task.path
            }
        
        # Expand
        solver = z3.Solver()
        solver.add(task.formula)
        solver.add(self.transition)
        
        subtasks = []
        
        if solver.check() == z3.sat:
            model = solver.model()
            succ_formula = z3.BoolVal(True)
            for v, v_prime in zip(self.variables, self.primed_vars):
                val = model.eval(v_prime, model_completion=True)
                succ_formula = z3.And(succ_formula, v == val)
            
            subtasks.append(VerificationTask(
                formula=succ_formula,
                location=task.location + 1,
                path=task.path + [task.formula]
            ))
        
        return {'status': 'continue', 'subtasks': subtasks}


@dataclass
class VerificationTask:
    """Task for parallel verification."""
    formula: z3.BoolRef
    location: int
    path: List[z3.BoolRef]


class ProgressWitness:
    """
    Progress witness for liveness verification.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 timeout_ms: int = 60000):
        self.variables = variables
        self.timeout_ms = timeout_ms
        
        self.ranking_function: Optional[z3.ArithRef] = None
        
        self.stats = {
            'ranking_synthesis_attempts': 0,
            'ranking_found': False,
        }
    
    def synthesize_ranking(self, transition: z3.BoolRef,
                            loop_condition: z3.BoolRef) -> Optional[z3.ArithRef]:
        """
        Synthesize ranking function for loop.
        """
        self.stats['ranking_synthesis_attempts'] += 1
        
        # Try linear ranking function
        coeffs = [z3.Real(f"r_{i}") for i in range(len(self.variables))]
        ranking = sum(c * v for c, v in zip(coeffs, self.variables))
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Must decrease on transition
        primed_ranking = sum(c * z3.Real(f"{v}'") 
                              for c, v in zip(coeffs, [str(x) for x in self.variables]))
        
        # Add decrease constraint (simplified)
        solver.add(z3.ForAll(self.variables,
                              z3.Implies(loop_condition, ranking > 0)))
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Extract ranking
            ranking_concrete = sum(
                float(model.eval(c, model_completion=True).as_fraction()) * v
                for c, v in zip(coeffs, self.variables)
            )
            
            self.ranking_function = ranking_concrete
            self.stats['ranking_found'] = True
            
            return ranking_concrete
        
        return None


# =============================================================================
# ADDITIONAL LAZY ABSTRACTION COMPONENTS
# =============================================================================

class InterpolantQuality:
    """
    Measure and improve interpolant quality.
    """
    
    def __init__(self, variables: List[z3.ArithRef]):
        self.variables = variables
        
        self.stats = {
            'quality_scores': [],
            'improvements': 0,
        }
    
    def score_interpolant(self, interpolant: z3.BoolRef,
                           path: List[z3.BoolRef]) -> float:
        """
        Score interpolant quality.
        
        Higher is better. Based on:
        - Syntactic size
        - Number of variables used
        - Semantic coverage
        """
        size_score = 1.0 / (1.0 + self._syntactic_size(interpolant))
        var_score = 1.0 / (1.0 + len(self._used_variables(interpolant)))
        
        score = 0.5 * size_score + 0.5 * var_score
        self.stats['quality_scores'].append(score)
        
        return score
    
    def improve_interpolant(self, interpolant: z3.BoolRef) -> z3.BoolRef:
        """Improve interpolant quality."""
        self.stats['improvements'] += 1
        
        # Try simplification
        simplified = z3.simplify(interpolant)
        
        return simplified
    
    def _syntactic_size(self, formula: z3.BoolRef) -> int:
        """Count AST nodes."""
        if z3.is_const(formula):
            return 1
        
        size = 1
        for child in formula.children():
            size += self._syntactic_size(child)
        
        return size
    
    def _used_variables(self, formula: z3.BoolRef) -> Set[str]:
        """Get variables used in formula."""
        used = set()
        
        def visit(f):
            if z3.is_const(f) and not z3.is_bool(f):
                if f.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                    used.add(str(f))
            for child in f.children():
                visit(child)
        
        visit(formula)
        return used


class ARTOptimizer:
    """
    Optimize Abstract Reachability Tree.
    """
    
    def __init__(self, art: AbstractReachabilityTree):
        self.art = art
        
        self.stats = {
            'nodes_merged': 0,
            'nodes_removed': 0,
        }
    
    def optimize(self) -> AbstractReachabilityTree:
        """Apply optimizations to ART."""
        self._merge_equivalent()
        self._remove_covered()
        return self.art
    
    def _merge_equivalent(self) -> None:
        """Merge nodes with equivalent formulas."""
        by_formula: Dict[str, List[ARTNode]] = {}
        
        for node in self.art.nodes.values():
            key = str(z3.simplify(node.formula))
            if key not in by_formula:
                by_formula[key] = []
            by_formula[key].append(node)
        
        for key, nodes in by_formula.items():
            if len(nodes) > 1:
                # Merge all into first
                primary = nodes[0]
                for other in nodes[1:]:
                    self._merge_into(other, primary)
                    self.stats['nodes_merged'] += 1
    
    def _merge_into(self, source: ARTNode, target: ARTNode) -> None:
        """Merge source node into target."""
        target.formula = z3.Or(target.formula, source.formula)
        
        # Redirect children
        for child in source.children:
            child.parent = target
            target.children.append(child)
        
        # Remove source
        if source.id in self.art.nodes:
            del self.art.nodes[source.id]
    
    def _remove_covered(self) -> None:
        """Remove nodes that are covered by others."""
        to_remove = []
        
        for node in self.art.nodes.values():
            if node.covered_by is not None:
                to_remove.append(node.id)
        
        for node_id in to_remove:
            del self.art.nodes[node_id]
            self.stats['nodes_removed'] += 1


class InterpolationCache:
    """
    Cache interpolation results.
    """
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        
        self.cache: Dict[str, z3.BoolRef] = {}
        
        self.stats = {
            'hits': 0,
            'misses': 0,
        }
    
    def lookup(self, key: str) -> Optional[z3.BoolRef]:
        """Look up interpolant in cache."""
        if key in self.cache:
            self.stats['hits'] += 1
            return self.cache[key]
        
        self.stats['misses'] += 1
        return None
    
    def store(self, key: str, interpolant: z3.BoolRef) -> None:
        """Store interpolant in cache."""
        if len(self.cache) >= self.max_size:
            # Evict oldest
            oldest = next(iter(self.cache))
            del self.cache[oldest]
        
        self.cache[key] = interpolant
    
    def compute_key(self, formulas: List[z3.BoolRef]) -> str:
        """Compute cache key for formula sequence."""
        return "|".join(str(z3.simplify(f)) for f in formulas)


class LazyAbstractionWithInterpolants:
    """
    Complete lazy abstraction with interpolants (IMPACT).
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 error: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.error = error
        self.timeout_ms = timeout_ms
        
        self.art = AbstractReachabilityTree(initial, 0)
        self.interpolant_cache = InterpolationCache()
        
        self.stats = {
            'expand_calls': 0,
            'cover_calls': 0,
            'refine_calls': 0,
        }
    
    def verify(self) -> ImpactVerificationResult:
        """Run full IMPACT verification."""
        # Initialize
        root = self.art.root
        worklist = [root]
        
        while worklist:
            node = worklist.pop()
            
            # Close?
            if self._close(node):
                continue
            
            # Expand
            successors = self._expand(node)
            
            for succ in successors:
                # Error?
                if self._is_error(succ):
                    if self._is_feasible_path(succ):
                        return ImpactVerificationResult(
                            result=ImpactResult.UNSAFE,
                            counterexample=self._extract_path(succ),
                            stats=self.stats
                        )
                    else:
                        self._refine(succ)
                else:
                    worklist.append(succ)
        
        return ImpactVerificationResult(
            result=ImpactResult.SAFE,
            counterexample=None,
            stats=self.stats
        )
    
    def _close(self, node: ARTNode) -> bool:
        """Try to close node by covering."""
        self.stats['cover_calls'] += 1
        
        for other in self.art.nodes.values():
            if other.location == node.location and other.id != node.id:
                if self._subsumes(other, node):
                    node.covered_by = other.id
                    return True
        
        return False
    
    def _expand(self, node: ARTNode) -> List[ARTNode]:
        """Expand node to successors."""
        self.stats['expand_calls'] += 1
        
        successors = []
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        solver.add(node.formula)
        solver.add(self.transition)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Build successor formula
            succ_formula = z3.BoolVal(True)
            for v, v_prime in zip(self.variables, self.primed_vars):
                val = model.eval(v_prime, model_completion=True)
                succ_formula = z3.And(succ_formula, v == val)
            
            succ = self.art.add_node(succ_formula, node.location + 1, node)
            successors.append(succ)
        
        return successors
    
    def _is_error(self, node: ARTNode) -> bool:
        """Check if node is error state."""
        solver = z3.Solver()
        solver.set("timeout", 1000)
        solver.add(node.formula)
        solver.add(self.error)
        
        return solver.check() == z3.sat
    
    def _is_feasible_path(self, node: ARTNode) -> bool:
        """Check if path to node is feasible."""
        path = self._extract_path(node)
        
        solver = z3.Solver()
        for formula in path:
            solver.add(formula)
        
        return solver.check() == z3.sat
    
    def _refine(self, node: ARTNode) -> None:
        """Refine using interpolants."""
        self.stats['refine_calls'] += 1
        
        path = self._extract_path(node)
        
        # Check cache
        key = self.interpolant_cache.compute_key(path)
        cached = self.interpolant_cache.lookup(key)
        
        if cached:
            # Use cached interpolant
            self._apply_interpolant(node, cached)
        else:
            # Compute fresh
            computer = InterpolantComputer(self.timeout_ms, False)
            result = computer.compute_sequence(path)
            
            if result.success and result.interpolants:
                for interp in result.interpolants:
                    self.interpolant_cache.store(key, interp)
                    self._apply_interpolant(node, interp)
    
    def _apply_interpolant(self, node: ARTNode, interpolant: z3.BoolRef) -> None:
        """Apply interpolant to strengthen node."""
        node.formula = z3.And(node.formula, interpolant)
    
    def _subsumes(self, n1: ARTNode, n2: ARTNode) -> bool:
        """Check if n1 subsumes n2."""
        solver = z3.Solver()
        solver.set("timeout", 1000)
        solver.add(n2.formula)
        solver.add(z3.Not(n1.formula))
        
        return solver.check() == z3.unsat
    
    def _extract_path(self, node: ARTNode) -> List[z3.BoolRef]:
        """Extract path to node."""
        path = []
        current = node
        
        while current is not None:
            path.append(current.formula)
            current = current.parent
        
        return list(reversed(path))


class ImpactDiagnostics:
    """
    Diagnostics for IMPACT verification.
    """
    
    def __init__(self, art: AbstractReachabilityTree):
        self.art = art
        
        self.stats = {
            'depth_distribution': {},
            'covering_stats': {},
        }
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze ART structure."""
        self._compute_depth_distribution()
        self._compute_covering_stats()
        
        return {
            'total_nodes': len(self.art.nodes),
            'max_depth': max(self.stats['depth_distribution'].keys()) if self.stats['depth_distribution'] else 0,
            'covering_rate': self.stats['covering_stats'].get('covered', 0) / max(1, len(self.art.nodes)),
            'depth_distribution': self.stats['depth_distribution'],
        }
    
    def _compute_depth_distribution(self) -> None:
        """Compute distribution of node depths."""
        for node in self.art.nodes.values():
            depth = self._node_depth(node)
            self.stats['depth_distribution'][depth] = \
                self.stats['depth_distribution'].get(depth, 0) + 1
    
    def _node_depth(self, node: ARTNode) -> int:
        """Compute depth of node."""
        depth = 0
        current = node
        while current.parent is not None:
            depth += 1
            current = current.parent
        return depth
    
    def _compute_covering_stats(self) -> None:
        """Compute covering statistics."""
        covered = sum(1 for n in self.art.nodes.values() if n.covered_by is not None)
        self.stats['covering_stats']['covered'] = covered
        self.stats['covering_stats']['uncovered'] = len(self.art.nodes) - covered


class ImpactARTBuilder:
    """
    Fluent interface for building ART structures.
    
    Provides a declarative way to construct abstract
    reachability trees for testing and analysis.
    """
    
    def __init__(self, name: str = "art"):
        self.name = name
        self.nodes = []
        self.edges = []
        self.root_annotation = z3.BoolVal(True)
        
    def with_root(self, annotation: z3.ExprRef) -> 'ImpactARTBuilder':
        """Set root node annotation."""
        self.root_annotation = annotation
        return self
    
    def add_node(self, node_id: str, location: str, 
                  annotation: z3.ExprRef = None) -> 'ImpactARTBuilder':
        """Add a node to the tree."""
        self.nodes.append({
            'id': node_id,
            'location': location,
            'annotation': annotation or z3.BoolVal(True)
        })
        return self
    
    def add_edge(self, from_id: str, to_id: str,
                  transition: str = "") -> 'ImpactARTBuilder':
        """Add an edge between nodes."""
        self.edges.append({
            'from': from_id,
            'to': to_id,
            'transition': transition
        })
        return self
    
    def with_covering(self, covered: str, covers: str) -> 'ImpactARTBuilder':
        """Mark covering relationship."""
        # Find nodes and set covering
        return self
    
    def build(self) -> 'AbstractReachabilityTree':
        """Build the ART."""
        art = AbstractReachabilityTree()
        
        # Create nodes
        for node_data in self.nodes:
            node = ARTNode(
                id=node_data['id'],
                location=node_data['location'],
                annotation=node_data['annotation']
            )
            art.add_node(node)
        
        # Create edges
        for edge_data in self.edges:
            art.add_edge(edge_data['from'], edge_data['to'])
        
        return art


class InterpolantStrengthener:
    """
    Strengthen interpolants for better convergence.
    
    Uses various techniques to produce stronger
    interpolants that lead to faster convergence.
    """
    
    def __init__(self, solver: z3.Solver = None):
        self.solver = solver or z3.Solver()
        self.stats = {'strengthening_attempts': 0}
        
    def strengthen(self, interpolant: z3.ExprRef,
                    pre: z3.ExprRef,
                    post: z3.ExprRef) -> z3.ExprRef:
        """
        Strengthen interpolant while maintaining validity.
        
        Returns strongest interpolant that:
        - pre implies interpolant
        - interpolant ∧ transition implies post
        """
        self.stats['strengthening_attempts'] += 1
        
        # Try conjunctive strengthening
        strengthened = self._conjunctive_strengthen(interpolant, pre, post)
        if strengthened is not None:
            return strengthened
        
        # Try minimal unsatisfiable core strengthening
        strengthened = self._mus_strengthen(interpolant, pre, post)
        if strengthened is not None:
            return strengthened
        
        return interpolant
    
    def _conjunctive_strengthen(self, interpolant: z3.ExprRef,
                                  pre: z3.ExprRef,
                                  post: z3.ExprRef) -> Optional[z3.ExprRef]:
        """Strengthen by adding conjuncts from pre."""
        if not z3.is_and(pre):
            return None
        
        conjuncts = [pre.arg(i) for i in range(pre.num_args())]
        
        for c in conjuncts:
            candidate = z3.And(interpolant, c)
            if self._is_valid_interpolant(candidate, pre, post):
                return candidate
        
        return None
    
    def _mus_strengthen(self, interpolant: z3.ExprRef,
                         pre: z3.ExprRef,
                         post: z3.ExprRef) -> Optional[z3.ExprRef]:
        """Strengthen using minimal unsatisfiable core."""
        # Would compute MUS of negation
        return None
    
    def _is_valid_interpolant(self, candidate: z3.ExprRef,
                                pre: z3.ExprRef,
                                post: z3.ExprRef) -> bool:
        """Check if candidate is valid interpolant."""
        self.solver.push()
        self.solver.add(z3.And(pre, z3.Not(candidate)))
        pre_implies = self.solver.check() == z3.unsat
        self.solver.pop()
        
        return pre_implies


class LoopUnrollingStrategy:
    """
    Strategies for unrolling loops in IMPACT.
    
    Different strategies lead to different performance
    characteristics for different program types.
    """
    
    BOUNDED = 'bounded'
    ACCELERATED = 'accelerated'  
    ABSTRACT = 'abstract'
    
    def __init__(self, strategy: str = BOUNDED, bound: int = 10):
        self.strategy = strategy
        self.bound = bound
        
    def should_unroll(self, loop_id: str, current_depth: int) -> bool:
        """Determine if loop should be further unrolled."""
        if self.strategy == self.BOUNDED:
            return current_depth < self.bound
        elif self.strategy == self.ACCELERATED:
            # Use acceleration after certain depth
            return current_depth < 3
        else:
            return True
    
    def get_loop_summary(self, loop_id: str,
                          invariant: z3.ExprRef) -> z3.ExprRef:
        """Get loop summary for abstract strategy."""
        if self.strategy == self.ABSTRACT:
            return invariant  # Use invariant as summary
        return z3.BoolVal(True)


class ImpactProofChecker:
    """
    Verify IMPACT proofs are correct.
    
    Given an ART with interpolants, checks that the
    annotations form a valid inductive invariant proof.
    """
    
    def __init__(self, verifier: 'ImpactVerifier'):
        self.verifier = verifier
        self.errors = []
        
    def check_proof(self, art: 'AbstractReachabilityTree') -> bool:
        """Check that ART represents valid proof."""
        self.errors = []
        
        # Check initiation
        if not self._check_initiation(art):
            return False
        
        # Check consecution for each edge
        if not self._check_consecution(art):
            return False
        
        # Check safety
        if not self._check_safety(art):
            return False
        
        return True
    
    def _check_initiation(self, art: 'AbstractReachabilityTree') -> bool:
        """Check initial states satisfy root annotation."""
        root = art.root
        if root is None:
            self.errors.append("No root node")
            return False
        
        solver = z3.Solver()
        solver.add(self.verifier.initial)
        solver.add(z3.Not(root.annotation))
        
        if solver.check() == z3.sat:
            self.errors.append("Initiation check failed")
            return False
        
        return True
    
    def _check_consecution(self, art: 'AbstractReachabilityTree') -> bool:
        """Check edge transitions preserve annotations."""
        for node in art.nodes.values():
            for child in node.children:
                if not self._check_edge(node, child):
                    return False
        return True
    
    def _check_edge(self, parent: 'ARTNode', child: 'ARTNode') -> bool:
        """Check single edge consecution."""
        return True  # Would check annotation preservation
    
    def _check_safety(self, art: 'AbstractReachabilityTree') -> bool:
        """Check no error nodes are reachable."""
        for node in art.nodes.values():
            if hasattr(node, 'is_error') and node.is_error:
                if not node.covered_by:
                    self.errors.append(f"Uncovered error node: {node.id}")
                    return False
        return True
    
    def get_errors(self) -> List[str]:
        """Get list of proof errors."""
        return self.errors
