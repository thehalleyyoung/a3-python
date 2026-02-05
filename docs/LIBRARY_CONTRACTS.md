# Library Contracts for Barrier-Based Bug Detection

## Integration with the 5-Layer Reduce-to-Barrier-via-Abstraction Framework

This document describes how **library contracts** fit into our 5-layer barrier synthesis architecture, with particular emphasis on **deferred constraint propagation**—the propagation of semantic information that does not immediately prove safety but enables later barrier proofs, either within the same procedure or across procedure boundaries.

---

## Table of Contents

1. [Core Insight: Deferred Barriers](#1-core-insight-deferred-barriers)
2. [The 5-Layer Barrier Synthesis Architecture](#2-the-5-layer-barrier-synthesis-architecture)
3. [Where Library Contracts Fit](#3-where-library-contracts-fit)
4. [The Interval Abstract Domain](#4-the-interval-abstract-domain)
5. [Deferred Constraint Propagation](#5-deferred-constraint-propagation)
6. [Integration with Each Layer](#6-integration-with-each-layer)
7. [Interprocedural Deferred Barriers](#7-interprocedural-deferred-barriers)
8. [Implementation](#8-implementation)
9. [Contract Catalog](#9-contract-catalog)

---

## 1. Core Insight: Deferred Barriers

### The Fundamental Problem

Consider this code:

```python
similarity = F.cosine_similarity(embedding1, embedding2)
# ... 50 lines of code ...
result = 1 / (similarity - 3)  # Is this safe?
```

A naive analyzer sees:
- `similarity` is some float (unknown range)
- `similarity - 3` could be 0
- **Report division-by-zero bug** ❌ FALSE POSITIVE

The key insight: `cosine_similarity` **always** returns values in `[-1, 1]`. Therefore:
- `similarity ∈ [-1, 1]`
- `similarity - 3 ∈ [-4, -2]`
- `0 ∉ [-4, -2]`
- **Division is safe** ✓

This information wasn't useful *at the call site*—it becomes useful *later* when we need to prove a barrier condition.

### Deferred Barriers Defined

A **Deferred Barrier** is a constraint that:
1. **Originates** from a library contract (or other semantic source)
2. **Propagates** through the program's abstract state
3. **Activates** when needed to prove a barrier certificate condition

Mathematically, if a library function `f` has contract `f(x) ∈ [a, b]`, and later we need to prove `f(x) - c ≠ 0`, the deferred barrier becomes:

$$B(x) = (f(x) - a)(b - f(x)) \geq 0 \land c \notin [a, b]$$

This is a **barrier certificate** in the sense of Prajna & Jadbabaie (2004): it separates the reachable states from the unsafe states.

---

## 2. The 5-Layer Barrier Synthesis Architecture

Our system uses a 5-layer architecture for synthesizing barrier certificates, as described in the technical presentation:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LAYER 5: IC3/PDR                                  │
│         Property-Directed Reachability with CHC Encoding            │
│         Complete verification via frame sequence construction       │
└─────────────────────────────────────────────────────────────────────┘
                                 ↑
┌─────────────────────────────────────────────────────────────────────┐
│                    LAYER 4: ICE Learning                            │
│         Implication + Counterexample + Equivalence samples          │
│         SyGuS templates, Houdini weakening                          │
└─────────────────────────────────────────────────────────────────────┘
                                 ↑
┌─────────────────────────────────────────────────────────────────────┐
│                    LAYER 3: CEGAR                                   │
│         Counter-Example Guided Abstraction Refinement               │
│         Craig interpolants, IMPACT algorithm                        │
└─────────────────────────────────────────────────────────────────────┘
                                 ↑
┌─────────────────────────────────────────────────────────────────────┐
│                 LAYERS 1-2: SOS/SDP Foundation                      │
│         Sum-of-Squares decomposition, Semidefinite Programming      │
│         Polynomial barrier templates via Positivstellensatz         │
└─────────────────────────────────────────────────────────────────────┘
                                 ↑
┌─────────────────────────────────────────────────────────────────────┐
│              LIBRARY CONTRACTS (This Document)                      │
│         Interval bounds, semantic constraints, deferred barriers    │
│         Feeds into all layers as domain knowledge                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Barrier Certificate Theory (Background)

A barrier certificate $B: \mathbb{R}^n \to \mathbb{R}$ proves that unsafe states are unreachable if:

1. **Initial Condition**: $B(x) \geq 0$ for all $x \in \text{Init}$
2. **Safety Condition**: $B(x) < 0$ for all $x \in \text{Unsafe}$
3. **Inductive Condition**: $\dot{B}(x) \geq 0$ whenever $B(x) = 0$

For discrete programs, the inductive condition becomes:
$$B(x) \geq 0 \implies B(f(x)) \geq 0$$

where $f$ is the transition function.

---

## 3. Where Library Contracts Fit

Library contracts serve as **axioms** in the barrier synthesis process. They provide:

| Contract Information | Barrier Synthesis Use |
|---------------------|----------------------|
| Return interval `[a, b]` | Polynomial constraints for SOS/SDP |
| Non-zero guarantee | Direct barrier certificate |
| Positive/negative guarantee | Sign-based barrier regions |
| Bounded derivative | Lipschitz constraints for induction |
| Shape preservation | Dimension-based feasibility |

### The Key Insight: Contracts as Barrier Generators

A library contract doesn't just provide *information*—it provides a **barrier certificate template**.

For `cosine_similarity(x, y) → [-1, 1]`:

```python
# The contract generates this barrier template:
def barrier_for_cosine_div(result, divisor_offset):
    """
    Barrier: B(r) = (r + 1)(1 - r) ≥ 0
    
    If divisor_offset ∉ [-1, 1], then:
      B(r - divisor_offset) < 0 for all r ∈ [-1, 1]
    
    Therefore: r - divisor_offset ≠ 0 for all reachable r
    """
    return (result + 1) * (1 - result)  # ≥ 0 for r ∈ [-1, 1]
```

---

## 4. The Interval Abstract Domain

### Definition

The interval abstract domain $\mathcal{I}$ represents sets of real numbers as closed intervals:

$$\mathcal{I} = \{[a, b] \mid a, b \in \mathbb{R} \cup \{-\infty, +\infty\}, a \leq b\} \cup \{\bot\}$$

where $\bot$ represents the empty set.

### Abstract Semantics

For each arithmetic operation, we define abstract counterparts:

```python
class Interval:
    def __init__(self, lo: float, hi: float):
        self.lo = lo
        self.hi = hi
    
    def __add__(self, other: 'Interval') -> 'Interval':
        """[a,b] + [c,d] = [a+c, b+d]"""
        return Interval(self.lo + other.lo, self.hi + other.hi)
    
    def __sub__(self, other: 'Interval') -> 'Interval':
        """[a,b] - [c,d] = [a-d, b-c]"""
        return Interval(self.lo - other.hi, self.hi - other.lo)
    
    def __mul__(self, other: 'Interval') -> 'Interval':
        """[a,b] * [c,d] = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)]"""
        products = [
            self.lo * other.lo, self.lo * other.hi,
            self.hi * other.lo, self.hi * other.hi
        ]
        return Interval(min(products), max(products))
    
    def __truediv__(self, other: 'Interval') -> 'Interval':
        """Division with zero-exclusion check"""
        if other.contains_zero():
            return Interval(-float('inf'), float('inf'))
        # [a,b] / [c,d] where 0 ∉ [c,d]
        if other.lo > 0:
            return Interval(self.lo / other.hi, self.hi / other.lo)
        else:  # other.hi < 0
            return Interval(self.hi / other.hi, self.lo / other.lo)
    
    def contains_zero(self) -> bool:
        return self.lo <= 0 <= self.hi
    
    def excludes_zero(self) -> bool:
        return self.hi < 0 or self.lo > 0
```

### Soundness Theorem

**Theorem (Interval Soundness)**: For any concrete operation $\odot \in \{+, -, \times, \div\}$ and intervals $I_1, I_2$:

$$\forall x \in I_1, y \in I_2: x \odot y \in I_1 \hat{\odot} I_2$$

where $\hat{\odot}$ is the abstract interval operation.

This soundness is *critical* for barrier proofs: if we prove $0 \notin I$, then *no concrete execution* can produce zero.

---

## 5. Deferred Constraint Propagation

### The Propagation Algorithm

Deferred constraints propagate through the abstract state as follows:

```python
class AbstractState:
    def __init__(self):
        self.intervals: Dict[str, Interval] = {}
        self.deferred_barriers: List[DeferredBarrier] = []
    
    def bind_library_result(self, var: str, contract: LibraryContract, args: List[Any]):
        """Bind a variable to a library call result with deferred constraints."""
        # Get the interval from the contract
        interval = contract.get_return_interval(args)
        self.intervals[var] = interval
        
        # Create a deferred barrier
        barrier = DeferredBarrier(
            variable=var,
            source_contract=contract,
            source_interval=interval,
            creation_point=self.current_location()
        )
        self.deferred_barriers.append(barrier)
    
    def propagate_through_operation(self, result_var: str, op: str, 
                                     left_var: str, right_operand: Any):
        """Propagate intervals and deferred barriers through an operation."""
        left_interval = self.intervals.get(left_var, Interval.TOP)
        
        if isinstance(right_operand, str):
            right_interval = self.intervals.get(right_operand, Interval.TOP)
        else:
            right_interval = Interval(right_operand, right_operand)
        
        # Compute result interval
        if op == '+':
            result_interval = left_interval + right_interval
        elif op == '-':
            result_interval = left_interval - right_interval
        elif op == '*':
            result_interval = left_interval * right_interval
        elif op == '/':
            result_interval = left_interval / right_interval
        
        self.intervals[result_var] = result_interval
        
        # Propagate deferred barriers
        for barrier in self.deferred_barriers:
            if barrier.variable == left_var:
                # Create derived barrier for the result
                derived = barrier.derive_through_operation(op, right_operand)
                derived.variable = result_var
                self.deferred_barriers.append(derived)
```

### Barrier Activation

When we encounter a potential bug (e.g., division), we check if any deferred barrier can prove safety:

```python
def check_division_safety(self, divisor_var: str) -> BarrierResult:
    """Check if division by divisor_var is safe using deferred barriers."""
    
    # First, check direct interval
    divisor_interval = self.intervals.get(divisor_var)
    if divisor_interval and divisor_interval.excludes_zero():
        return BarrierResult.SAFE_BY_INTERVAL
    
    # Check deferred barriers
    for barrier in self.deferred_barriers:
        if barrier.variable == divisor_var:
            if barrier.proves_nonzero():
                return BarrierResult.SAFE_BY_DEFERRED_BARRIER
    
    # No barrier found - potential bug
    return BarrierResult.POTENTIALLY_UNSAFE
```

### Example: cosine_similarity - 3

```python
# Step 1: Library call
similarity = F.cosine_similarity(x, y)
# State: intervals = {similarity: [-1, 1]}
#        deferred_barriers = [DeferredBarrier(var=similarity, interval=[-1,1])]

# Step 2: Subtraction
diff = similarity - 3
# Interval propagation: [-1, 1] - [3, 3] = [-4, -2]
# State: intervals = {similarity: [-1, 1], diff: [-4, -2]}
#        deferred_barriers = [
#            DeferredBarrier(var=similarity, interval=[-1,1]),
#            DeferredBarrier(var=diff, interval=[-4,-2], derived_from=similarity)
#        ]

# Step 3: Division check
result = 1 / diff
# Check: diff.excludes_zero()? 
#        [-4, -2].excludes_zero() = True (since -2 < 0)
# Result: SAFE_BY_INTERVAL

# The deferred barrier proves: ∀s ∈ [-1,1]: s - 3 ∈ [-4,-2], and 0 ∉ [-4,-2]
```

---

## 6. Integration with Each Layer

### Layer 1-2: SOS/SDP Integration

Library contracts provide **polynomial constraints** for the SOS/SDP solver:

```python
def contract_to_sos_constraints(contract: LibraryContract, var: Symbol) -> List[Polynomial]:
    """
    Convert a library contract to SOS polynomial constraints.
    
    For interval [a, b], we get:
      (var - a) ≥ 0   (lower bound)
      (b - var) ≥ 0   (upper bound)
    
    Combined as SOS:
      (var - a)(b - var) ≥ 0
    """
    a, b = contract.return_interval
    
    # Barrier polynomial: B(var) = (var - a)(b - var)
    # This is ≥ 0 iff var ∈ [a, b]
    barrier_poly = (var - a) * (b - var)
    
    # For SOS, we need: B(var) = σ(var) where σ is SOS
    # This is automatically SOS for quadratics of this form
    return [barrier_poly]

def check_safety_via_sos(divisor_poly: Polynomial, contract_constraints: List[Polynomial]) -> bool:
    """
    Use Positivstellensatz to check if divisor_poly ≠ 0 under contract constraints.
    
    We want to prove: ∃ SOS polynomials σ₀, σ₁, ... such that
      -1 = σ₀ + Σᵢ σᵢ · gᵢ + divisor_poly · h
    
    This is infeasible iff divisor_poly ≠ 0 on the constraint set.
    """
    # Encode as SDP problem
    sdp = SDPProblem()
    
    for constraint in contract_constraints:
        sdp.add_constraint(constraint >= 0)
    
    # Check if divisor_poly = 0 is reachable
    sdp.add_objective(divisor_poly == 0)
    
    result = sdp.solve()
    return result == INFEASIBLE  # Safe if no solution
```

**Example SOS Encoding**:

For `cosine_similarity(x, y) - 3`:
- Contract gives: `result ∈ [-1, 1]`
- Barrier polynomial: $B(r) = (r + 1)(1 - r) = -r^2 + 1$
- For divisor $r - 3$, we check: does $\exists r: B(r) \geq 0 \land r - 3 = 0$?
- Substituting $r = 3$: $B(3) = (3+1)(1-3) = 4 \cdot (-2) = -8 < 0$
- Since $B(3) < 0$, $r = 3$ is not in the reachable region → **SAFE**

### Layer 3: CEGAR Integration

Library contracts provide **predicates** for abstraction refinement:

```python
def contract_to_cegar_predicates(contract: LibraryContract, var: str) -> List[Predicate]:
    """
    Convert library contract to CEGAR predicates.
    
    These predicates are used in:
    1. Initial abstraction
    2. Counterexample analysis
    3. Refinement via Craig interpolation
    """
    a, b = contract.return_interval
    
    predicates = [
        Predicate(f"{var} >= {a}"),  # Lower bound
        Predicate(f"{var} <= {b}"),  # Upper bound
    ]
    
    # For signed intervals, add sign predicates
    if a >= 0:
        predicates.append(Predicate(f"{var} >= 0"))  # Non-negative
    elif b <= 0:
        predicates.append(Predicate(f"{var} <= 0"))  # Non-positive
    
    return predicates

def analyze_cegar_counterexample(cex: Counterexample, contracts: Dict[str, LibraryContract]) -> Refinement:
    """
    Analyze a CEGAR counterexample using contract knowledge.
    
    If the counterexample violates a contract, we can refine by adding
    the contract predicate to the abstraction.
    """
    for var, value in cex.variable_assignments.items():
        if var in contracts:
            contract = contracts[var]
            a, b = contract.return_interval
            
            if not (a <= value <= b):
                # Counterexample violates contract - spurious!
                # Use Craig interpolation to get refinement predicate
                interpolant = craig_interpolate(
                    premise=f"{var} = library_call(...)",
                    conclusion=f"{a} <= {var} <= {b}"
                )
                return Refinement(new_predicate=interpolant)
    
    return Refinement(is_real_bug=True)
```

**IMPACT Algorithm Integration**:

```
CEGAR Loop with Contracts:
  1. Abstract program using contract predicates
  2. Check abstract safety
  3. If safe → done
  4. If unsafe → get counterexample trace
  5. Check if trace violates any contract
     - If yes → spurious, refine with contract predicate
     - If no → real bug
  6. Repeat
```

### Layer 4: ICE Learning Integration

Library contracts provide **training samples** for ICE (Implication-Counterexample-Equivalence) learning:

```python
def contract_to_ice_samples(contract: LibraryContract, var: str) -> ICESamples:
    """
    Generate ICE samples from a library contract.
    
    S⁺: Positive samples (definitely safe states)
    S⁻: Negative samples (definitely unsafe states)  
    S→: Implication samples (state transitions)
    """
    a, b = contract.return_interval
    
    # Positive samples: points inside the interval
    positive = [
        {var: a},           # Boundary
        {var: b},           # Boundary
        {var: (a + b) / 2}, # Midpoint
    ]
    
    # Negative samples: points outside the interval
    epsilon = 0.001
    negative = [
        {var: a - epsilon},  # Just below lower bound
        {var: b + epsilon},  # Just above upper bound
        {var: a - 1},        # Well below
        {var: b + 1},        # Well above
    ]
    
    # Implication samples: the interval is preserved under the identity
    implications = [
        ({var: a}, {var: a}),  # a → a
        ({var: b}, {var: b}),  # b → b
    ]
    
    return ICESamples(
        positive=positive,
        negative=negative,
        implications=implications
    )

def learn_barrier_with_contracts(ice_samples: ICESamples, 
                                  template: BarrierTemplate) -> Barrier:
    """
    Use ICE learning to find a barrier consistent with contract samples.
    
    Template: B(x) = Σᵢ cᵢ · fᵢ(x) where fᵢ are basis functions
    
    Learn coefficients cᵢ such that:
      - B(s) ≥ 0 for all s ∈ S⁺
      - B(s) < 0 for all s ∈ S⁻
      - B(s) ≥ 0 → B(s') ≥ 0 for all (s, s') ∈ S→
    """
    learner = ICELearner(template)
    
    for sample in ice_samples.positive:
        learner.add_positive_constraint(sample)
    
    for sample in ice_samples.negative:
        learner.add_negative_constraint(sample)
    
    for pre, post in ice_samples.implications:
        learner.add_implication_constraint(pre, post)
    
    return learner.solve()
```

**Houdini Weakening with Contracts**:

```python
def houdini_with_contracts(candidates: List[Predicate], 
                           contracts: Dict[str, LibraryContract]) -> List[Predicate]:
    """
    Houdini algorithm enhanced with contract knowledge.
    
    Start with contract-derived predicates as candidates.
    Iteratively remove predicates that are not inductive.
    """
    # Initialize with contract predicates
    for var, contract in contracts.items():
        a, b = contract.return_interval
        candidates.extend([
            Predicate(f"{var} >= {a}"),
            Predicate(f"{var} <= {b}"),
        ])
    
    # Standard Houdini loop
    changed = True
    while changed:
        changed = False
        for pred in list(candidates):
            if not is_inductive(pred, candidates):
                candidates.remove(pred)
                changed = True
    
    return candidates
```

### Layer 5: IC3/PDR Integration

Library contracts become **CHC clauses** for the IC3/PDR solver:

```python
def contract_to_chc(contract: LibraryContract, 
                    call_site: CallSite,
                    result_var: str) -> CHCClause:
    """
    Encode a library contract as a Constrained Horn Clause.
    
    CHC form:
      ∀args. Pre(args) → Post(result_var)
    
    For interval contract [a, b]:
      ∀args. true → (result_var >= a ∧ result_var <= b)
    """
    a, b = contract.return_interval
    
    # The clause asserts: after calling the library function,
    # the result is within the contract bounds
    clause = CHCClause(
        head=f"lib_post_{call_site.id}({result_var})",
        body=[
            f"lib_call_{call_site.id}({', '.join(call_site.args)})",
        ],
        constraint=f"{result_var} >= {a} && {result_var} <= {b}"
    )
    
    return clause

def ic3_with_contracts(cfg: ControlFlowGraph, 
                       contracts: Dict[str, LibraryContract],
                       property: SafetyProperty) -> VerificationResult:
    """
    IC3/PDR verification with contract-derived CHC clauses.
    
    Frame sequence: F₀ ⊆ F₁ ⊆ ... ⊆ Fₖ
    
    Each frame Fᵢ represents states reachable in ≤i steps.
    Contract clauses constrain what's possible after library calls.
    """
    # Initialize frames
    F = [property.init_region]
    
    # Add contract clauses to the CHC system
    chc_system = CHCSystem()
    for call_site in cfg.library_calls():
        if call_site.function in contracts:
            clause = contract_to_chc(
                contracts[call_site.function],
                call_site,
                call_site.result_var
            )
            chc_system.add_clause(clause)
    
    # IC3 main loop
    while True:
        # Try to block bad states using frames + contract knowledge
        if not can_reach_unsafe(F[-1], property.unsafe_region, chc_system):
            # Check for fixed point
            if F[-1] == F[-2]:
                return VerificationResult.SAFE
            F.append(F[-1].clone())
        else:
            # Get counterexample, check if it violates contracts
            cex = get_counterexample()
            if violates_contracts(cex, contracts):
                # Block with contract-derived clause
                blocking_clause = derive_blocking_clause(cex, contracts)
                generalize_and_add(blocking_clause, F)
            else:
                return VerificationResult.UNSAFE(cex)
```

**Spacer Integration** (Z3's CHC solver):

```python
def encode_for_spacer(program: Program, contracts: Dict[str, LibraryContract]) -> str:
    """
    Encode program + contracts as CHC for Z3 Spacer solver.
    """
    smt = []
    
    # Declare relations
    smt.append("(declare-rel entry ())")
    smt.append("(declare-rel error ())")
    
    for func in program.functions:
        smt.append(f"(declare-rel {func.name} ({func.param_sorts}))")
    
    # Encode contracts as rules
    for func_name, contract in contracts.items():
        a, b = contract.return_interval
        smt.append(f"""
        (rule (=> (and ({func_name} result) 
                       (>= result {a}) 
                       (<= result {b}))
                  ({func_name}_post result)))
        """)
    
    # Encode program transitions with contract post-conditions
    for edge in program.cfg.edges:
        if edge.is_library_call and edge.callee in contracts:
            smt.append(f"""
            (rule (=> (and {edge.pre_state}
                           ({edge.callee}_post {edge.result_var}))
                      {edge.post_state}))
            """)
    
    # Query: is error reachable?
    smt.append("(query error)")
    
    return "\n".join(smt)
```

---

## 7. Interprocedural Deferred Barriers

### The Challenge

Deferred constraints must flow across procedure boundaries:

```python
def compute_similarity(x, y):
    return F.cosine_similarity(x, y)  # Returns [-1, 1]

def use_similarity(x, y):
    sim = compute_similarity(x, y)  # What's the range here?
    return 1 / (sim - 5)  # Is this safe?
```

The constraint `sim ∈ [-1, 1]` must propagate from `compute_similarity` to `use_similarity`.

### Contract Summaries

We compute **function summaries** that include deferred barriers:

```python
@dataclass
class FunctionSummary:
    """Summary of a function's behavior including deferred constraints."""
    
    # Parameter constraints (precondition)
    parameter_constraints: Dict[str, Interval]
    
    # Return value constraint (postcondition)
    return_interval: Optional[Interval]
    
    # Deferred barriers that propagate to callers
    exported_barriers: List[DeferredBarrier]
    
    # Library contracts used internally
    internal_contracts: List[LibraryContract]

def compute_summary(func: Function, contracts: ContractRegistry) -> FunctionSummary:
    """
    Compute a function summary by abstract interpretation.
    """
    # Initialize abstract state
    state = AbstractState()
    
    # Analyze function body
    for stmt in func.body:
        if is_library_call(stmt):
            contract = contracts.get(stmt.callee)
            if contract:
                state.bind_library_result(stmt.result, contract, stmt.args)
        elif is_return(stmt):
            # The return value's interval becomes the summary's return_interval
            return_interval = state.intervals.get(stmt.value)
            # Deferred barriers on return value are exported
            exported = [b for b in state.deferred_barriers if b.variable == stmt.value]
            return FunctionSummary(
                return_interval=return_interval,
                exported_barriers=exported,
                ...
            )
        else:
            state.execute_abstract(stmt)
    
    return FunctionSummary(...)
```

### Call Graph Analysis

We analyze the call graph to propagate summaries:

```python
def interprocedural_analysis(program: Program, contracts: ContractRegistry):
    """
    Fixed-point interprocedural analysis with contract propagation.
    """
    summaries: Dict[str, FunctionSummary] = {}
    worklist = list(program.functions)
    
    while worklist:
        func = worklist.pop()
        
        # Compute summary using current summaries of callees
        new_summary = compute_summary(func, contracts, summaries)
        
        if new_summary != summaries.get(func.name):
            summaries[func.name] = new_summary
            # Re-analyze callers
            for caller in func.callers:
                if caller not in worklist:
                    worklist.append(caller)
    
    return summaries
```

### Context Sensitivity (2-CFA)

We use 2-CFA for precision in deferred barrier propagation:

```python
@dataclass
class Context:
    """2-CFA context: the last 2 call sites."""
    call_sites: Tuple[CallSite, CallSite]

def analyze_with_context(func: Function, context: Context, 
                          contracts: ContractRegistry) -> FunctionSummary:
    """
    Context-sensitive analysis.
    
    Different call contexts may have different deferred barriers:
    
    def wrapper(use_cosine: bool, x, y):
        if use_cosine:
            return F.cosine_similarity(x, y)  # [-1, 1]
        else:
            return F.pairwise_distance(x, y)  # [0, ∞)
    
    Callers need different summaries depending on the context.
    """
    # Use context to specialize the analysis
    ...
```

---

## 8. Implementation

### Core Data Structures

```python
# In pyfromscratch/contracts/base.py

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Any, Callable
import math

class Interval:
    """
    Interval abstract domain with full arithmetic propagation.
    
    Supports:
    - Addition, subtraction, multiplication, division
    - Comparison operations
    - Widening for fixed-point computation
    """
    
    def __init__(self, lo: float = -math.inf, hi: float = math.inf):
        self.lo = lo
        self.hi = hi
    
    @classmethod
    def TOP(cls) -> 'Interval':
        return cls(-math.inf, math.inf)
    
    @classmethod
    def BOTTOM(cls) -> 'Interval':
        return cls(math.inf, -math.inf)  # Empty interval
    
    @classmethod
    def point(cls, v: float) -> 'Interval':
        return cls(v, v)
    
    def is_empty(self) -> bool:
        return self.lo > self.hi
    
    def contains_zero(self) -> bool:
        return self.lo <= 0 <= self.hi
    
    def excludes_zero(self) -> bool:
        return self.hi < 0 or self.lo > 0
    
    def __add__(self, other: 'Interval') -> 'Interval':
        return Interval(self.lo + other.lo, self.hi + other.hi)
    
    def __sub__(self, other: 'Interval') -> 'Interval':
        return Interval(self.lo - other.hi, self.hi - other.lo)
    
    def __mul__(self, other: 'Interval') -> 'Interval':
        products = [
            self.lo * other.lo, self.lo * other.hi,
            self.hi * other.lo, self.hi * other.hi
        ]
        # Handle inf * 0 = nan
        products = [p for p in products if not math.isnan(p)]
        if not products:
            return Interval.TOP()
        return Interval(min(products), max(products))
    
    def __truediv__(self, other: 'Interval') -> 'Interval':
        if other.contains_zero():
            # Division by interval containing zero - could be anything
            if other.lo == 0 and other.hi == 0:
                return Interval.BOTTOM()  # Division by exactly zero
            # Split: [lo, 0) ∪ (0, hi]
            return Interval.TOP()
        
        # Safe division
        if other.lo > 0:
            return Interval(self.lo / other.hi, self.hi / other.lo)
        else:  # other.hi < 0
            return Interval(self.hi / other.hi, self.lo / other.lo)
    
    def join(self, other: 'Interval') -> 'Interval':
        """Least upper bound (union overapproximation)."""
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))
    
    def meet(self, other: 'Interval') -> 'Interval':
        """Greatest lower bound (intersection)."""
        return Interval(max(self.lo, other.lo), min(self.hi, other.hi))
    
    def widen(self, other: 'Interval') -> 'Interval':
        """Widening for convergence."""
        lo = self.lo if other.lo >= self.lo else -math.inf
        hi = self.hi if other.hi <= self.hi else math.inf
        return Interval(lo, hi)


class BarrierStrength(Enum):
    """Strength of a barrier proof."""
    NONE = auto()           # No barrier found
    HEURISTIC = auto()      # Based on patterns/heuristics
    INTERVAL = auto()       # Proven by interval analysis
    CONTRACT = auto()       # Proven by library contract
    DEFERRED = auto()       # Proven by deferred barrier propagation
    SOS = auto()            # Proven by SOS/SDP
    CEGAR = auto()          # Proven by CEGAR refinement
    IC3 = auto()            # Proven by IC3/PDR


@dataclass
class DeferredBarrier:
    """
    A constraint that may prove safety later in the analysis.
    
    Created when a library function is called, propagated through
    operations, activated when needed to prove a barrier condition.
    """
    variable: str
    source_contract: 'LibraryContract'
    source_interval: Interval
    current_interval: Interval
    creation_location: Optional[str] = None
    transformations: List[str] = field(default_factory=list)
    
    def derive_through_operation(self, op: str, operand: Any) -> 'DeferredBarrier':
        """Create a derived barrier after an arithmetic operation."""
        if isinstance(operand, (int, float)):
            operand_interval = Interval.point(operand)
        elif isinstance(operand, Interval):
            operand_interval = operand
        else:
            operand_interval = Interval.TOP()
        
        if op == '+':
            new_interval = self.current_interval + operand_interval
        elif op == '-':
            new_interval = self.current_interval - operand_interval
        elif op == '*':
            new_interval = self.current_interval * operand_interval
        elif op == '/':
            new_interval = self.current_interval / operand_interval
        else:
            new_interval = Interval.TOP()
        
        return DeferredBarrier(
            variable=self.variable,
            source_contract=self.source_contract,
            source_interval=self.source_interval,
            current_interval=new_interval,
            creation_location=self.creation_location,
            transformations=self.transformations + [f"{op} {operand}"]
        )
    
    def proves_nonzero(self) -> bool:
        """Check if this barrier proves the variable is non-zero."""
        return self.current_interval.excludes_zero()
    
    def get_barrier_polynomial(self, var_symbol) -> Any:
        """
        Get the barrier polynomial for SOS/SDP verification.
        
        B(x) = (x - lo)(hi - x) ≥ 0 for x ∈ [lo, hi]
        """
        lo, hi = self.current_interval.lo, self.current_interval.hi
        if math.isinf(lo) or math.isinf(hi):
            return None
        return (var_symbol - lo) * (hi - var_symbol)


@dataclass 
class LibraryContract:
    """
    Semantic contract for a library function.
    
    Specifies:
    - Return value interval
    - Preconditions on arguments
    - Side effects
    - Barrier generation capability
    """
    function_name: str
    module: str
    return_interval: Optional[Interval] = None
    return_interval_fn: Optional[Callable] = None
    guarantees_nonzero: bool = False
    guarantees_positive: bool = False
    guarantees_nonnegative: bool = False
    preconditions: Dict[str, Interval] = field(default_factory=dict)
    description: str = ""
    
    def get_return_interval(self, args: List[Any] = None) -> Interval:
        """Get the return interval, possibly depending on arguments."""
        if self.return_interval_fn and args:
            return self.return_interval_fn(args)
        if self.return_interval:
            return self.return_interval
        
        # Derive from guarantees
        if self.guarantees_positive:
            return Interval(1e-10, math.inf)  # Strictly positive
        if self.guarantees_nonnegative:
            return Interval(0, math.inf)
        if self.guarantees_nonzero:
            return Interval.TOP()  # Could be anything except zero
        
        return Interval.TOP()
    
    def creates_barrier(self) -> bool:
        """Check if this contract creates a useful barrier."""
        return (self.return_interval is not None or 
                self.return_interval_fn is not None or
                self.guarantees_nonzero or
                self.guarantees_positive or
                self.guarantees_nonnegative)
    
    def to_ice_samples(self, var: str) -> Dict[str, List]:
        """Generate ICE samples for learning."""
        interval = self.get_return_interval()
        if interval.is_empty() or math.isinf(interval.lo) and math.isinf(interval.hi):
            return {'positive': [], 'negative': [], 'implications': []}
        
        positive = []
        negative = []
        
        if not math.isinf(interval.lo):
            positive.append({var: interval.lo})
            negative.append({var: interval.lo - 0.001})
        
        if not math.isinf(interval.hi):
            positive.append({var: interval.hi})
            negative.append({var: interval.hi + 0.001})
        
        if not math.isinf(interval.lo) and not math.isinf(interval.hi):
            positive.append({var: (interval.lo + interval.hi) / 2})
        
        return {
            'positive': positive,
            'negative': negative,
            'implications': []
        }


class ContractRegistry:
    """Registry of all library contracts."""
    
    def __init__(self):
        self.contracts: Dict[str, LibraryContract] = {}
    
    def register(self, contract: LibraryContract):
        key = f"{contract.module}.{contract.function_name}"
        self.contracts[key] = contract
    
    def get(self, module: str, function: str) -> Optional[LibraryContract]:
        key = f"{module}.{function}"
        return self.contracts.get(key)
    
    def get_by_name(self, name: str) -> Optional[LibraryContract]:
        """Get contract by function name alone (for unqualified calls)."""
        for key, contract in self.contracts.items():
            if contract.function_name == name:
                return contract
        return None
```

### PyTorch Contract Examples

```python
# In pyfromscratch/contracts/torch_contracts.py

from .base import LibraryContract, Interval, ContractRegistry
import math

def register_torch_contracts(registry: ContractRegistry):
    """Register all PyTorch contracts."""
    
    # ============ SIMILARITY FUNCTIONS ============
    # These are critical for deferred barrier propagation
    
    registry.register(LibraryContract(
        function_name="cosine_similarity",
        module="torch.nn.functional",
        return_interval=Interval(-1.0, 1.0),
        description="Cosine similarity is always in [-1, 1] by definition"
    ))
    
    registry.register(LibraryContract(
        function_name="pairwise_distance", 
        module="torch.nn.functional",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="Distance is always non-negative"
    ))
    
    # ============ ACTIVATION FUNCTIONS ============
    
    registry.register(LibraryContract(
        function_name="sigmoid",
        module="torch",
        return_interval=Interval(0.0, 1.0),
        description="Sigmoid output is in (0, 1), approximated as [0, 1]"
    ))
    
    registry.register(LibraryContract(
        function_name="tanh",
        module="torch",
        return_interval=Interval(-1.0, 1.0),
        description="Tanh output is in (-1, 1), approximated as [-1, 1]"
    ))
    
    registry.register(LibraryContract(
        function_name="softmax",
        module="torch.nn.functional",
        return_interval=Interval(0.0, 1.0),
        description="Softmax outputs are probabilities in [0, 1]"
    ))
    
    registry.register(LibraryContract(
        function_name="relu",
        module="torch.nn.functional", 
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="ReLU output is non-negative"
    ))
    
    registry.register(LibraryContract(
        function_name="softplus",
        module="torch.nn.functional",
        return_interval=Interval(0.0, math.inf),
        guarantees_positive=True,
        description="Softplus is always positive"
    ))
    
    registry.register(LibraryContract(
        function_name="elu",
        module="torch.nn.functional",
        return_interval=Interval(-1.0, math.inf),  # With default alpha=1
        description="ELU is bounded below by -alpha"
    ))
    
    # ============ EXPONENTIAL FAMILY ============
    
    registry.register(LibraryContract(
        function_name="exp",
        module="torch",
        return_interval=Interval(0.0, math.inf),
        guarantees_positive=True,
        description="Exponential is always positive"
    ))
    
    registry.register(LibraryContract(
        function_name="log",
        module="torch",
        return_interval=Interval(-math.inf, math.inf),
        preconditions={"input": Interval(0.0, math.inf)},
        description="Log is defined for positive inputs"
    ))
    
    registry.register(LibraryContract(
        function_name="log_softmax",
        module="torch.nn.functional",
        return_interval=Interval(-math.inf, 0.0),
        description="Log-softmax outputs are non-positive"
    ))
    
    # ============ NORM FUNCTIONS ============
    
    registry.register(LibraryContract(
        function_name="norm",
        module="torch",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="Norm is always non-negative"
    ))
    
    registry.register(LibraryContract(
        function_name="normalize",
        module="torch.nn.functional",
        # Returns unit vector, so each element is in [-1, 1]
        return_interval=Interval(-1.0, 1.0),
        description="Normalized vectors have elements in [-1, 1]"
    ))
    
    # ============ REDUCTION FUNCTIONS ============
    
    registry.register(LibraryContract(
        function_name="sum",
        module="torch",
        return_interval=Interval(-math.inf, math.inf),
        # Note: Could be refined with input knowledge
        description="Sum can be anything depending on input"
    ))
    
    registry.register(LibraryContract(
        function_name="mean",
        module="torch",
        return_interval=Interval(-math.inf, math.inf),
        description="Mean is within the range of input elements"
    ))
    
    # ============ SIZE/SHAPE FUNCTIONS ============
    # These return positive integers
    
    registry.register(LibraryContract(
        function_name="size",
        module="torch.Tensor",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="Size is always non-negative integer"
    ))
    
    registry.register(LibraryContract(
        function_name="numel",
        module="torch.Tensor",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="Number of elements is non-negative"
    ))
    
    registry.register(LibraryContract(
        function_name="dim",
        module="torch.Tensor",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="Number of dimensions is non-negative"
    ))
    
    # ============ PROBABILITY FUNCTIONS ============
    
    registry.register(LibraryContract(
        function_name="bernoulli",
        module="torch",
        return_interval=Interval(0.0, 1.0),
        description="Bernoulli samples are 0 or 1"
    ))
    
    registry.register(LibraryContract(
        function_name="rand",
        module="torch",
        return_interval=Interval(0.0, 1.0),
        description="Uniform random in [0, 1)"
    ))
    
    registry.register(LibraryContract(
        function_name="randn",
        module="torch",
        return_interval=Interval(-math.inf, math.inf),
        description="Normal random, unbounded but concentrated near 0"
    ))
    
    # ============ CLAMP FUNCTIONS ============
    
    def clamp_interval(args):
        """Compute clamp return interval from arguments."""
        if len(args) >= 3:
            min_val = args[1] if args[1] is not None else -math.inf
            max_val = args[2] if args[2] is not None else math.inf
            return Interval(min_val, max_val)
        return Interval.TOP()
    
    registry.register(LibraryContract(
        function_name="clamp",
        module="torch",
        return_interval_fn=clamp_interval,
        description="Clamp restricts output to [min, max]"
    ))
    
    registry.register(LibraryContract(
        function_name="clamp_min",
        module="torch",
        return_interval_fn=lambda args: Interval(args[1], math.inf) if len(args) > 1 else Interval.TOP(),
        description="Clamp minimum"
    ))
    
    registry.register(LibraryContract(
        function_name="clamp_max",
        module="torch",
        return_interval_fn=lambda args: Interval(-math.inf, args[1]) if len(args) > 1 else Interval.TOP(),
        description="Clamp maximum"
    ))
    
    # ============ ABS/SIGN FUNCTIONS ============
    
    registry.register(LibraryContract(
        function_name="abs",
        module="torch",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="Absolute value is non-negative"
    ))
    
    registry.register(LibraryContract(
        function_name="sign",
        module="torch",
        return_interval=Interval(-1.0, 1.0),
        description="Sign is -1, 0, or 1"
    ))
    
    registry.register(LibraryContract(
        function_name="sgn",
        module="torch",
        return_interval=Interval(-1.0, 1.0),
        description="Signum is -1, 0, or 1"
    ))
    
    # ============ TRIGONOMETRIC ============
    
    registry.register(LibraryContract(
        function_name="sin",
        module="torch",
        return_interval=Interval(-1.0, 1.0),
        description="Sine is in [-1, 1]"
    ))
    
    registry.register(LibraryContract(
        function_name="cos",
        module="torch",
        return_interval=Interval(-1.0, 1.0),
        description="Cosine is in [-1, 1]"
    ))
    
    # ============ LOSS FUNCTIONS ============
    
    registry.register(LibraryContract(
        function_name="mse_loss",
        module="torch.nn.functional",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="MSE loss is non-negative"
    ))
    
    registry.register(LibraryContract(
        function_name="l1_loss",
        module="torch.nn.functional",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="L1 loss is non-negative"
    ))
    
    registry.register(LibraryContract(
        function_name="cross_entropy",
        module="torch.nn.functional",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="Cross-entropy loss is non-negative"
    ))
    
    registry.register(LibraryContract(
        function_name="nll_loss",
        module="torch.nn.functional",
        return_interval=Interval(-math.inf, math.inf),  # Can be negative with log_softmax
        description="NLL loss sign depends on input"
    ))
    
    registry.register(LibraryContract(
        function_name="binary_cross_entropy",
        module="torch.nn.functional",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="BCE loss is non-negative"
    ))
    
    registry.register(LibraryContract(
        function_name="kl_div",
        module="torch.nn.functional",
        return_interval=Interval(0.0, math.inf),
        guarantees_nonnegative=True,
        description="KL divergence is non-negative"
    ))
```

---

## 9. Contract Catalog

### Summary Table

| Function | Module | Return Interval | Barrier Use |
|----------|--------|-----------------|-------------|
| `cosine_similarity` | `torch.nn.functional` | `[-1, 1]` | `f(x)-c ≠ 0` for `c ∉ [-1,1]` |
| `sigmoid` | `torch` | `[0, 1]` | Non-negative, bounded |
| `tanh` | `torch` | `[-1, 1]` | Bounded |
| `softmax` | `torch.nn.functional` | `[0, 1]` | Probability bounds |
| `relu` | `torch.nn.functional` | `[0, ∞)` | Non-negative |
| `exp` | `torch` | `(0, ∞)` | Strictly positive |
| `norm` | `torch` | `[0, ∞)` | Non-negative |
| `abs` | `torch` | `[0, ∞)` | Non-negative |
| `sin`, `cos` | `torch` | `[-1, 1]` | Bounded |
| `mse_loss` | `torch.nn.functional` | `[0, ∞)` | Non-negative |
| `cross_entropy` | `torch.nn.functional` | `[0, ∞)` | Non-negative |
| `pairwise_distance` | `torch.nn.functional` | `[0, ∞)` | Non-negative |
| `log_softmax` | `torch.nn.functional` | `(-∞, 0]` | Non-positive |
| `normalize` | `torch.nn.functional` | `[-1, 1]` | Unit vector |
| `clamp` | `torch` | `[min, max]` | Argument-dependent |

### Barrier Proof Patterns

**Pattern 1: Bounded Similarity Offset**
```python
sim = F.cosine_similarity(x, y)  # ∈ [-1, 1]
# For any offset c where |c| > 1:
result = 1 / (sim - c)  # SAFE: sim - c ≠ 0
```

**Pattern 2: Positive Guarantee**
```python
loss = F.mse_loss(pred, target)  # ∈ [0, ∞)
# Adding any non-negative constant:
denom = loss + epsilon  # > 0 if epsilon > 0
result = scale / denom  # SAFE
```

**Pattern 3: Activation Bounds**
```python
prob = torch.sigmoid(logits)  # ∈ [0, 1]
complement = 1 - prob  # ∈ [0, 1]
# Both prob and complement are in [0, 1]
# Division by (prob * complement) needs care at boundaries
```

**Pattern 4: Norm Non-Negativity**
```python
n = torch.norm(tensor)  # ∈ [0, ∞)
if n > threshold:
    normalized = tensor / n  # SAFE if threshold > 0
```

---

## Appendix A: Formal Soundness

**Theorem (Contract Soundness)**: If a library function `f` has contract $f: \mathbb{R}^n \to [a, b]$, and the analyzer proves that $0 \notin [a, b] - c$ for some constant $c$, then $f(x) - c \neq 0$ for all inputs $x$.

*Proof*: By interval soundness, $\forall x: f(x) \in [a, b]$. Thus $\forall x: f(x) - c \in [a-c, b-c]$. If $0 \notin [a-c, b-c]$, then $\forall x: f(x) - c \neq 0$. ∎

**Theorem (Deferred Barrier Propagation)**: If a deferred barrier $B$ with interval $I$ is derived through operations $o_1, \ldots, o_k$ to produce interval $I'$, then $I'$ soundly overapproximates all possible results.

*Proof*: By induction on the operation sequence, using the soundness of each interval operation. ∎

---

## Appendix B: Adding New Contracts

To add a contract for a new library:

```python
# 1. Create the contract file
# pyfromscratch/contracts/mylib_contracts.py

from .base import LibraryContract, Interval, ContractRegistry

def register_mylib_contracts(registry: ContractRegistry):
    registry.register(LibraryContract(
        function_name="my_function",
        module="mylib",
        return_interval=Interval(lower_bound, upper_bound),
        guarantees_positive=True,  # If applicable
        description="Description of the function semantics"
    ))

# 2. Register in the main contract loader
# pyfromscratch/contracts/__init__.py

def load_all_contracts() -> ContractRegistry:
    registry = ContractRegistry()
    register_torch_contracts(registry)
    register_numpy_contracts(registry)
    register_mylib_contracts(registry)  # Add here
    return registry
```

---

## Appendix C: Relationship to Barrier Certificate Theory

The connection between library contracts and barrier certificates:

1. **Contracts as Semi-Algebraic Sets**: Each interval constraint $x \in [a, b]$ defines a semi-algebraic set $\{x : (x-a)(b-x) \geq 0\}$

2. **SOS Representation**: The constraint $(x-a)(b-x) \geq 0$ is automatically a Sum-of-Squares polynomial in disguise (it's quadratic with roots at $a$ and $b$, negative outside)

3. **Barrier Induction**: For discrete transitions $x' = f(x)$, if both $x$ and $x'$ satisfy the contract, the barrier is inductive

4. **Positivstellensatz Application**: To prove $g(x) > 0$ under contract constraints, we use:
   $$-1 = \sigma_0(x) + \sigma_1(x)(x-a) + \sigma_2(x)(b-x) + g(x) \cdot h(x)$$
   where $\sigma_i$ are SOS polynomials. This is infeasible iff $g(x) > 0$ on $[a,b]$.

---

*Document Version: 2.0*
*Last Updated: February 2026*
*Framework: 5-Layer Barrier Synthesis with Deferred Constraint Propagation*
