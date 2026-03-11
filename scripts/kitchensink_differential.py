#!/usr/bin/env python3
"""
Kitchensink Differential: Find bugs/code where A³+kitchensink diagnoses
differently than A³−kitchensink.

Tests all 20 papers and their composition, not just BMC.

Architecture recap:
  Kitchensink pipeline:
    GOAL 1: BMC + Stochastic Replay  → can find bugs (early return)
    GOAL 2: Papers #1,3,4-5,9        → local safety proofs (barriers, SOS, DSOS)
    GOAL 3: Papers #18,17,10,19      → invariant discovery (Houdini, ICE, IC3, SyGuS)
    GOAL 4: Papers #6,7,8,2          → polynomial barrier synthesis (SOS-SDP, Lasserre, Sparse, Stochastic)
    GOAL 5: Papers #13,12,14,16,15,11→ abstraction-refinement (CEGAR, Predicate, IMC, CHC)
    GOAL 6: Paper #20                → compositional reasoning (Assume-Guarantee)
    GOAL 7: Semantic bug types        → contract, temporal, dataflow, protocol, resource
    FALLBACK: baseline analyze_file()

  Non-kitchensink: just analyze_file() (AST detectors + symbolic execution)

Differentials can occur at:
  - Verdict level (BMC/stochastic find bugs baseline misses)
  - Per-bug-type level (barrier proofs enriching/contradicting baseline)
  - Diagnostic detail level (more specific bug classification)
"""

import json
import os
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from a3_python.analyzer import Analyzer, AnalysisResult


# ============================================================================
# Test case definitions — one per paper group / composition
# ============================================================================

@dataclass
class TestCase:
    """A test case targeting specific kitchensink paper(s)."""
    name: str
    papers: List[int]  # Paper numbers targeted
    goal: int           # Which GOAL (1-7) this targets
    code: str           # Python source
    description: str    # What this tests
    expected_ks_advantage: str  # What kitchensink should uniquely catch


TEST_CASES: List[TestCase] = [
    # ────────────────────────────────────────────────────────────────────
    # GOAL 1: BMC + Stochastic Replay
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="bmc_deep_branch_bug",
        papers=[0],  # BMC (not a numbered paper, part of infrastructure)
        goal=1,
        description="Bug hidden behind deeply nested branches — BMC's BFS finds it faster",
        expected_ks_advantage="BMC finds DIVISION_BY_ZERO via breadth-first; baseline DFS may hit step limit",
        code=textwrap.dedent("""\
            # Deeply nested conditional leading to division by zero
            x = 10
            y = 5
            z = 3
            
            if x > 0:
                if y > 0:
                    if z > 0:
                        w = x - y - z  # w = 2
                        if w > 1:
                            w = w - 1   # w = 1
                            if w > 0:
                                w = w - 1  # w = 0
                                result = 100 / w  # DIVISION BY ZERO!
        """),
    ),
    TestCase(
        name="bmc_loop_counter_bug",
        papers=[0],
        goal=1,
        description="Loop counter reaches zero creating div-by-zero, needs precise iteration tracking",
        expected_ks_advantage="BMC unrolls loop precisely finding exact iteration where k=0",
        code=textwrap.dedent("""\
            # Loop drives a counter to zero, then divides
            k = 5
            for i in range(5):
                k = k - 1
            # k is now 0
            result = 100 / k  # DIVISION BY ZERO after loop
        """),
    ),
    TestCase(
        name="stochastic_rare_path_bug",
        papers=[0],
        goal=1,
        description="Bug on a rare execution path that stochastic testing might catch",
        expected_ks_advantage="Stochastic replay explores random concrete executions to find the failing path",
        code=textwrap.dedent("""\
            # Only crashes when all three conditions align
            import sys
            data = [1, 2, 3, 0, 5]
            total = 0
            count = 0
            for item in data:
                total += item
                if item != 0:
                    count += 1
            # count = 4, total = 11
            # But if data had different values, count could be 0
            # The real bug: what if ALL items are zero?
            # Force the bug trigger:
            data2 = [0, 0, 0]
            total2 = 0
            count2 = 0
            for item in data2:
                total2 += item
                if item != 0:
                    count2 += 1
            avg = total2 / count2  # DIVISION BY ZERO - count2 is 0
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # GOAL 2: LOCAL SAFETY PROOFS
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="hscc04_barrier_safe_div",
        papers=[1],
        goal=2,
        description="Division inside a loop where the divisor is provably positive (barrier certificate)",
        expected_ks_advantage="Paper #1 (HSCC'04) synthesizes barrier proving divisor > 0 always; baseline says UNKNOWN",
        code=textwrap.dedent("""\
            # Loop with division that is SAFE - divisor stays positive
            # The barrier certificate B(n) = n proves n > 0 in the loop
            n = 10
            total = 0
            while n > 0:
                total += 100 / n  # SAFE: n > 0 is loop guard
                n = n - 1
        """),
    ),
    TestCase(
        name="sos_emptiness_safe_guard",
        papers=[3],
        goal=2,
        description="Guarded hazard where SOS proves the guard makes the hazard unreachable",
        expected_ks_advantage="Paper #3 SOS emptiness proves x*x+y*y > 0 when (x,y) != (0,0)",
        code=textwrap.dedent("""\
            # Division is safe because guard ensures denominator != 0
            x = 5
            y = 3
            if x != 0 or y != 0:
                denom = x * x + y * y  # Always > 0 when (x,y) != (0,0)
                result = 1.0 / denom   # SAFE
        """),
    ),
    TestCase(
        name="dsos_sdsos_fast_relaxation",
        papers=[9],
        goal=2,
        description="Safety proof via DSOS/SDSOS LP relaxation (faster than full SDP)",
        expected_ks_advantage="Paper #9 DSOS/SDSOS proves safety via LP/SOCP, cheaper than SOS-SDP",
        code=textwrap.dedent("""\
            # Loop safety provable by DSOS (diagonal dominance)
            a = 1
            b = 1
            for i in range(20):
                a_new = a + b
                b_new = a
                a = a_new
                b = b_new
            # Fibonacci - a,b always positive, no overflow in range(20)
            result = 100 / a  # SAFE: a is always positive in Fibonacci
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # GOAL 3: INVARIANT DISCOVERY
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="houdini_conjunctive_invariant",
        papers=[18],
        goal=3,
        description="Simple conjunctive invariant: x > 0 AND y > 0 maintained by loop",
        expected_ks_advantage="Paper #18 Houdini discovers x>0 ∧ y>0 is inductive, proving div safe",
        code=textwrap.dedent("""\
            # Houdini should discover: x > 0 AND y > 0 is invariant
            x = 10
            y = 20
            for i in range(10):
                x = x - 1 + 2  # x stays > 0 (increases by 1 each time)
                y = y - 1      # y decreases but starts at 20, 10 iterations
                if x > 0 and y > 0:
                    ratio = x / y  # SAFE if Houdini proves invariant
        """),
    ),
    TestCase(
        name="ice_learning_nonlinear_invariant",
        papers=[17],
        goal=3,
        description="Nonlinear invariant: x*y > 0, learned from positive/negative examples",
        expected_ks_advantage="Paper #17 ICE learns invariant from implication counterexamples",
        code=textwrap.dedent("""\
            # ICE should learn: x*y > 0 is preserved by the loop
            x = 2
            y = 3
            for i in range(5):
                x = x + 1
                y = y + 1
            # x = 7, y = 8, product = 56, always positive
            result = 100 / (x * y)  # SAFE: x*y > 0
        """),
    ),
    TestCase(
        name="ic3_pdr_reachability",
        papers=[10],
        goal=3,
        description="Property-directed reachability: prove error state unreachable by induction",
        expected_ks_advantage="Paper #10 IC3/PDR proves error unreachable via relative inductive clauses",
        code=textwrap.dedent("""\
            # IC3/PDR should prove the error branch is unreachable
            state = 0  # FSM: 0 -> 1 -> 2 -> 0 (cycle)
            for i in range(12):
                if state == 0:
                    state = 1
                elif state == 1:
                    state = 2
                elif state == 2:
                    state = 0
                else:
                    # ERROR: unreachable state!
                    result = 1 / 0  # Should be proven unreachable
            # After loop, state is always in {0, 1, 2}
        """),
    ),
    TestCase(
        name="sygus_synthesis_ranking",
        papers=[19],
        goal=3,
        description="SyGuS synthesizes a loop summary/ranking function",
        expected_ks_advantage="Paper #19 SyGuS synthesizes expressions fitting the loop pattern",
        code=textwrap.dedent("""\
            # SyGuS should synthesize: after loop, n = 0
            n = 100
            while n > 0:
                n = n - 1
            # n is guaranteed to be 0 after loop
            if n == 0:
                result = 42  # SAFE path
            else:
                result = 1 / 0  # Should be unreachable
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # GOAL 4: POLYNOMIAL BARRIER SYNTHESIS
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="parrilo_sos_sdp_quadratic",
        papers=[6],
        goal=4,
        description="Quadratic barrier B(x,y) = x² + y² - r² separates init from unsafe",
        expected_ks_advantage="Paper #6 Parrilo SOS-SDP finds polynomial certificate of safety",
        code=textwrap.dedent("""\
            # Quadratic dynamics with polynomial safety certificate
            x = 1.0
            y = 0.0
            for i in range(50):
                # Rotation: x,y stay on unit circle
                x_new = x * 0.99 - y * 0.01
                y_new = x * 0.01 + y * 0.99
                x = x_new
                y = y_new
            # x² + y² ≈ 1 always, never reaches 0
            denom = x * x + y * y
            result = 1.0 / denom  # SAFE: bounded away from 0
        """),
    ),
    TestCase(
        name="lasserre_hierarchy_degree4",
        papers=[7],
        goal=4,
        description="Requires degree-4 barrier; Lasserre hierarchy lifts from degree-2 to degree-4",
        expected_ks_advantage="Paper #7 Lasserre incrementally deepens degree until barrier found",
        code=textwrap.dedent("""\
            # Needs degree-4 barrier: B(x,y) = (x²+y²)² - 1
            x = 0.5
            y = 0.5
            for i in range(10):
                # Contraction towards origin
                x = x * 0.9
                y = y * 0.9
            # x² + y² shrinks but stays > 0
            sq = x * x + y * y
            result = 1.0 / sq  # SAFE 
        """),
    ),
    TestCase(
        name="sparse_sos_clique",
        papers=[8],
        goal=4,
        description="Large state space but sparse coupling - clique decomposition helps",
        expected_ks_advantage="Paper #8 Sparse SOS decomposes into cliques for scalability",
        code=textwrap.dedent("""\
            # Multiple independent subsystems (sparse coupling)
            a = 10
            b = 20
            c = 30
            d = 40
            # Subsystem 1: a, b
            for i in range(5):
                a = a + 1
                b = b - 1
            # Subsystem 2: c, d (independent)
            for j in range(5):
                c = c + 2
                d = d - 1
            # Each subsystem provably safe separately
            result1 = 100 / a   # SAFE: a = 15
            result2 = 100 / b   # SAFE: b = 15
            result3 = 100 / c   # SAFE: c = 40
            result4 = 100 / d   # SAFE: d = 35
        """),
    ),
    TestCase(
        name="stochastic_barrier_probabilistic",
        papers=[2],
        goal=4,
        description="Probabilistic safety: bound probability of reaching unsafe state",
        expected_ks_advantage="Paper #2 stochastic barrier bounds P(unsafe) ≤ ε",
        code=textwrap.dedent("""\
            # Stochastic dynamics: random walk with drift
            import random
            random.seed(42)
            x = 10.0
            for i in range(20):
                step = random.gauss(0, 1)
                x = x + step + 0.5  # Drift towards +∞
            # With positive drift, P(x ≤ 0) is negligible
            if x > 0:
                result = 100 / x  # Likely SAFE with high probability
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # GOAL 5: ABSTRACTION-REFINEMENT
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="predicate_abstraction_boolean",
        papers=[13],
        goal=5,
        description="Predicate abstraction reduces numeric program to Boolean predicates",
        expected_ks_advantage="Paper #13 abstracts to predicates {x>0, y>0, done}, proving safety",
        code=textwrap.dedent("""\
            # Predicate abstraction can reduce this to a Boolean program
            x = 5
            done = False
            while not done:
                if x > 1:
                    x = x - 1
                else:
                    done = True
            # After loop: x == 1 and done == True
            result = 100 / x  # SAFE: x is always 1 here
        """),
    ),
    TestCase(
        name="cegar_refinement_loop",
        papers=[12],
        goal=5,
        description="CEGAR refines abstract model until spurious counterexample eliminated",
        expected_ks_advantage="Paper #12 CEGAR: initial abstraction too coarse, refinement eliminates false alarm",
        code=textwrap.dedent("""\
            # CEGAR refines abstraction to prove array access is safe
            data = [1, 2, 3, 4, 5]
            idx = 0
            total = 0
            while idx < len(data):
                total += data[idx]  # SAFE: idx in [0, len-1]
                idx += 1
            # After loop: idx == len(data), total = 15
            result = total  # SAFE
        """),
    ),
    TestCase(
        name="imc_interpolation_proof",
        papers=[15],
        goal=5,
        description="Craig interpolation proves safety by constructing intermediate formulas",
        expected_ks_advantage="Paper #15 IMC uses interpolation between pre and post formulae",
        code=textwrap.dedent("""\
            # Interpolation between loop entry and error
            x = 0
            y = 100
            for i in range(10):
                x = x + 2
                y = y - 3
            # x = 20, y = 70
            # Interpolant: x + y > 0
            if x + y <= 0:
                result = 1 / 0  # UNREACHABLE: x + y = 90 > 0
        """),
    ),
    TestCase(
        name="spacer_chc_horn_clauses",
        papers=[11],
        goal=5,
        description="CHC solving: encode loop as constrained Horn clauses, solve with Spacer",
        expected_ks_advantage="Paper #11 Spacer solves Horn clauses encoding the transition system",
        code=textwrap.dedent("""\
            # Horn clause encoding: Inv(x) :- x = 0.   Inv(x+1) :- Inv(x), x < 10.
            x = 0
            while x < 10:
                x = x + 1
            # x == 10 guaranteed
            if x != 10:
                result = 1 / 0  # UNREACHABLE per CHC solution
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # GOAL 6: COMPOSITIONAL REASONING
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="assume_guarantee_composition",
        papers=[20],
        goal=6,
        description="Multi-function program: assume-guarantee decomposes into per-function contracts",
        expected_ks_advantage="Paper #20 verifies each function with assumed contracts of callees",
        code=textwrap.dedent("""\
            # Compositional: validate() guarantees x > 0, process() assumes it
            def validate(x):
                if x <= 0:
                    return 1  # Ensures positive
                return x
            
            def process(x):
                # Assumes x > 0 (guaranteed by validate)
                return 100 / x  # SAFE if called after validate
            
            raw = -5
            safe_val = validate(raw)
            result = process(safe_val)  # SAFE: validate ensures > 0
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # GOAL 7: SEMANTIC BUG TYPE VERIFICATION
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="contract_precondition_violation",
        papers=[1, 13, 17],
        goal=7,
        description="Precondition violation: function called with argument outside its domain",
        expected_ks_advantage="Kitchensink contract verification detects violated precondition",
        code=textwrap.dedent("""\
            # Contract: sqrt requires x >= 0
            import math
            
            def compute_distance(x1, x2):
                diff = x1 - x2
                # BUG: diff can be negative, passed to sqrt
                return math.sqrt(diff)  # PRECONDITION: diff >= 0
            
            d = compute_distance(3, 7)  # diff = -4, sqrt(-4) raises ValueError
        """),
    ),
    TestCase(
        name="temporal_use_after_close",
        papers=[10, 13, 16],
        goal=7,
        description="Resource used after being closed — temporal safety violation",
        expected_ks_advantage="Kitchensink temporal verification tracks resource lifecycle",
        code=textwrap.dedent("""\
            # Temporal bug: use after close
            class Connection:
                def __init__(self):
                    self.closed = False
                def close(self):
                    self.closed = True
                def query(self, sql):
                    if self.closed:
                        raise RuntimeError("Connection closed")
                    return sql
            
            conn = Connection()
            conn.close()
            result = conn.query("SELECT 1")  # BUG: use after close!
        """),
    ),
    TestCase(
        name="dataflow_unvalidated_input",
        papers=[13, 17, 20],
        goal=7,
        description="Unvalidated external input flows to sensitive sink",
        expected_ks_advantage="Kitchensink dataflow verification tracks taint from source to sink",
        code=textwrap.dedent("""\
            # Dataflow bug: unvalidated input used as array index
            user_input = int("999")  # Could be anything
            data = [1, 2, 3, 4, 5]
            
            # BUG: no bounds check on user_input
            result = data[user_input]  # INDEX_OUT_OF_BOUNDS
        """),
    ),
    TestCase(
        name="protocol_iterator_violation",
        papers=[10, 14, 16],
        goal=7,
        description="Iterator protocol violation: modifying collection during iteration",
        expected_ks_advantage="Kitchensink protocol verification detects iterator invalidation",
        code=textwrap.dedent("""\
            # Protocol bug: modifying list during iteration
            items = [1, 2, 3, 4, 5]
            for item in items:
                if item % 2 == 0:
                    items.remove(item)  # BUG: modifying during iteration
            # items will skip element 4 (undefined behavior)
        """),
    ),
    TestCase(
        name="resource_unbounded_allocation",
        papers=[2, 7, 19],
        goal=7,
        description="Unbounded memory allocation in a loop",
        expected_ks_advantage="Kitchensink resource verification detects potential memory exhaustion",
        code=textwrap.dedent("""\
            # Resource bug: unbounded list growth
            results = []
            n = 10
            while n > 0:
                results.append([0] * 1000000)  # Allocating 1M list each iteration
                n -= 1
            # Not properly bounded by available memory
        """),
    ),

    # ────────────────────────────────────────────────────────────────────
    # COMPOSITION TESTS: Multiple papers working together
    # ────────────────────────────────────────────────────────────────────
    TestCase(
        name="composition_houdini_sos_barrier",
        papers=[18, 6, 1],
        goal=99,  # Composition
        description="Houdini finds invariant, SOS certifies it, barrier proves safety",
        expected_ks_advantage="Composition: Houdini+SOS+Barrier is stronger than any single technique",
        code=textwrap.dedent("""\
            # Need sequential composition:
            # 1. Houdini finds candidate: x + y > 0
            # 2. SOS certifies it's inductive
            # 3. Barrier separates from div-by-zero
            x = 5
            y = 5
            for i in range(8):
                if x > y:
                    x = x - 1
                    y = y + 2
                else:
                    x = x + 2
                    y = y - 1
            # x + y is always positive and grows
            result = 100 / (x + y)  # SAFE
        """),
    ),
    TestCase(
        name="composition_cegar_ic3_predicate",
        papers=[12, 10, 13],
        goal=99,  # Composition
        description="CEGAR+IC3+Predicate abstraction for state machine verification",
        expected_ks_advantage="Composition: CEGAR refines, IC3 proves reachability, predicates track state",
        code=textwrap.dedent("""\
            # State machine: need CEGAR+IC3 to prove error unreachable
            mode = "init"
            counter = 0
            for i in range(20):
                if mode == "init":
                    if counter >= 3:
                        mode = "ready"
                    counter += 1
                elif mode == "ready":
                    if counter >= 10:
                        mode = "done"
                    counter += 1
                elif mode == "done":
                    break
                else:
                    # ERROR: impossible state
                    result = 1 / 0
            # mode is always in {"init", "ready", "done"}
        """),
    ),
    TestCase(
        name="composition_all_papers_complex",
        papers=list(range(1, 21)),
        goal=99,  # All papers
        description="Complex program requiring multiple paper techniques",
        expected_ks_advantage="Full portfolio: each paper contributes partial proof, composition proves safety",
        code=textwrap.dedent("""\
            # Complex program needing the full portfolio
            import math
            
            # Phase 1: Numeric computation (SOS/barrier for safety)
            x = 1.0
            y = 1.0
            for i in range(10):
                x = x + 0.1 * y
                y = y - 0.05 * x
            # x,y stay bounded
            
            # Phase 2: Discrete state machine (IC3/CEGAR for reachability)
            state = 0
            transitions = 0
            while state != 3 and transitions < 100:
                if state == 0:
                    state = 1
                elif state == 1:
                    state = 2
                elif state == 2:
                    state = 3
                transitions += 1
            
            # Phase 3: Compositional property (assume-guarantee)
            safe_x = max(x, 0.001)   # Ensure positive via guard
            safe_state = state + 1    # state=3, so safe_state=4
            
            # Combined result uses both numeric and discrete properties  
            result = safe_x / safe_state  # SAFE: both > 0
        """),
    ),
]


# ============================================================================
# Differential analysis runner
# ============================================================================

@dataclass
class DifferentialResult:
    """Result of comparing kitchensink vs non-kitchensink analysis."""
    test_name: str
    papers: List[int]
    goal: int
    
    # Verdicts
    ks_verdict: str
    no_ks_verdict: str
    verdict_diff: bool
    
    # Bug types
    ks_bug_type: Optional[str]
    no_ks_bug_type: Optional[str]
    bug_type_diff: bool
    
    # Per-bug-type enrichment from kitchensink
    ks_per_bug_type: Dict[str, Any]
    no_ks_per_bug_type: Dict[str, Any]
    per_bug_type_diff: bool
    
    # Messages
    ks_message: Optional[str]
    no_ks_message: Optional[str]
    
    # Timing
    ks_time_s: float
    no_ks_time_s: float
    
    # Paths explored
    ks_paths: int
    no_ks_paths: int

    @property
    def has_differential(self) -> bool:
        return self.verdict_diff or self.bug_type_diff or self.per_bug_type_diff


def _run_analysis_worker(filepath_str: str, kitchensink: bool, verbose: bool,
                         result_dict: dict):
    """Worker function for multiprocessing-based timeout."""
    filepath = Path(filepath_str)
    analyzer = Analyzer(
        max_depth=300,
        max_paths=100,
        verbose=verbose,
    )
    
    start = time.time()
    try:
        if kitchensink:
            result = analyzer.analyze_file_kitchensink(filepath)
        else:
            result = analyzer.analyze_file(filepath)
        elapsed = time.time() - start
        result_dict['verdict'] = result.verdict
        result_dict['bug_type'] = result.bug_type
        result_dict['message'] = result.message
        result_dict['paths_explored'] = result.paths_explored or 0
        result_dict['per_bug_type'] = result.per_bug_type or {}
        result_dict['elapsed'] = elapsed
    except Exception as e:
        elapsed = time.time() - start
        result_dict['verdict'] = 'ERROR'
        result_dict['bug_type'] = None
        result_dict['message'] = f"{type(e).__name__}: {e}"
        result_dict['paths_explored'] = 0
        result_dict['per_bug_type'] = {}
        result_dict['elapsed'] = elapsed


def run_analysis(filepath: Path, kitchensink: bool, verbose: bool = False,
                 timeout: int = 45) -> Tuple[AnalysisResult, float]:
    """Run A³ analysis with or without kitchensink, with hard process timeout."""
    import multiprocessing
    
    manager = multiprocessing.Manager()
    result_dict = manager.dict()
    
    p = multiprocessing.Process(
        target=_run_analysis_worker,
        args=(str(filepath), kitchensink, verbose, result_dict)
    )
    p.start()
    p.join(timeout=timeout)
    
    if p.is_alive():
        p.kill()
        p.join(timeout=5)
        return AnalysisResult(verdict="TIMEOUT", message=f"Killed after {timeout}s"), float(timeout)
    
    if 'verdict' not in result_dict:
        return AnalysisResult(verdict="ERROR", message="Worker crashed"), 0.0
    
    elapsed = result_dict.get('elapsed', 0.0)
    result = AnalysisResult(
        verdict=result_dict['verdict'],
        bug_type=result_dict.get('bug_type'),
        message=result_dict.get('message'),
        paths_explored=result_dict.get('paths_explored', 0),
        per_bug_type=dict(result_dict.get('per_bug_type', {})),
    )
    return result, elapsed


def run_differential(tc: TestCase, verbose: bool = False) -> DifferentialResult:
    """Run one test case with and without kitchensink, compare results."""
    # Write test code to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, prefix=f'ks_{tc.name}_') as f:
        f.write(tc.code)
        tmppath = Path(f.name)
    
    try:
        # Run with kitchensink
        ks_result, ks_time = run_analysis(tmppath, kitchensink=True, verbose=verbose)
        
        # Run without kitchensink
        no_ks_result, no_ks_time = run_analysis(tmppath, kitchensink=False, verbose=verbose)
        
        # Extract per_bug_type info
        ks_pbt = ks_result.per_bug_type or {}
        no_ks_pbt = no_ks_result.per_bug_type or {}
        
        # Compute diffs
        verdict_diff = ks_result.verdict != no_ks_result.verdict
        bug_type_diff = ks_result.bug_type != no_ks_result.bug_type
        
        # per_bug_type diff: kitchensink has entries that baseline doesn't
        ks_only_bug_types = set(ks_pbt.keys()) - set(no_ks_pbt.keys())
        per_bug_type_diff = bool(ks_only_bug_types)
        
        return DifferentialResult(
            test_name=tc.name,
            papers=tc.papers,
            goal=tc.goal,
            ks_verdict=ks_result.verdict,
            no_ks_verdict=no_ks_result.verdict,
            verdict_diff=verdict_diff,
            ks_bug_type=ks_result.bug_type,
            no_ks_bug_type=no_ks_result.bug_type,
            bug_type_diff=bug_type_diff,
            ks_per_bug_type={k: _summarize_pbt(v) for k, v in ks_pbt.items()},
            no_ks_per_bug_type={k: _summarize_pbt(v) for k, v in no_ks_pbt.items()},
            per_bug_type_diff=per_bug_type_diff,
            ks_message=ks_result.message,
            no_ks_message=no_ks_result.message,
            ks_time_s=round(ks_time, 3),
            no_ks_time_s=round(no_ks_time, 3),
            ks_paths=ks_result.paths_explored or 0,
            no_ks_paths=no_ks_result.paths_explored or 0,
        )
    finally:
        tmppath.unlink(missing_ok=True)


def _summarize_pbt(v):
    """Make per_bug_type values JSON-serializable."""
    if isinstance(v, dict):
        result = {}
        for k2, v2 in v.items():
            if k2 == "proofs":
                result[k2] = f"[{len(v2)} proof(s)]" if isinstance(v2, list) else str(v2)
            else:
                result[k2] = str(v2)
        return result
    return str(v)


# ============================================================================
# Main
# ============================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Kitchensink Differential Analysis")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output per analysis")
    parser.add_argument("--goal", type=int, help="Only run tests for a specific GOAL number")
    parser.add_argument("--test", type=str, help="Only run a specific test by name")
    parser.add_argument("--json", type=str, help="Output results as JSON to file")
    args = parser.parse_args()
    
    # Filter tests
    tests = TEST_CASES
    if args.goal:
        tests = [t for t in tests if t.goal == args.goal]
    if args.test:
        tests = [t for t in tests if t.name == args.test]
    
    print(f"Running {len(tests)} kitchensink differential tests...")
    print("=" * 80)
    
    results: List[DifferentialResult] = []
    differentials = 0
    
    for i, tc in enumerate(tests, 1):
        papers_str = ",".join(f"#{p}" for p in tc.papers)
        print(f"\n[{i}/{len(tests)}] {tc.name} (GOAL {tc.goal}, Papers: {papers_str})")
        print(f"  {tc.description}")
        
        try:
            dr = run_differential(tc, verbose=args.verbose)
            results.append(dr)
            
            # Print comparison
            ks_str = f"{dr.ks_verdict}"
            if dr.ks_bug_type:
                ks_str += f" ({dr.ks_bug_type})"
            ks_str += f" [{dr.ks_time_s}s, {dr.ks_paths} paths]"
            
            no_ks_str = f"{dr.no_ks_verdict}"
            if dr.no_ks_bug_type:
                no_ks_str += f" ({dr.no_ks_bug_type})"
            no_ks_str += f" [{dr.no_ks_time_s}s, {dr.no_ks_paths} paths]"
            
            diff_marker = " ***DIFFERENTIAL***" if dr.has_differential else ""
            print(f"  + kitchensink: {ks_str}")
            print(f"  - kitchensink: {no_ks_str}")
            
            if dr.verdict_diff:
                print(f"  ⚡ VERDICT DIFF: {dr.ks_verdict} vs {dr.no_ks_verdict}")
                differentials += 1
            elif dr.bug_type_diff:
                print(f"  ⚡ BUG TYPE DIFF: {dr.ks_bug_type} vs {dr.no_ks_bug_type}")
                differentials += 1
            elif dr.per_bug_type_diff:
                ks_only = set(dr.ks_per_bug_type.keys()) - set(dr.no_ks_per_bug_type.keys())
                print(f"  ⚡ PER-BUG-TYPE DIFF: kitchensink has extra types: {ks_only}")
                differentials += 1
            else:
                print(f"  ≡ Same result")
            
            # Show kitchensink-only per_bug_type if any
            if dr.ks_per_bug_type:
                ks_only_types = set(dr.ks_per_bug_type.keys()) - set(dr.no_ks_per_bug_type.keys())
                if ks_only_types:
                    for bt in ks_only_types:
                        info = dr.ks_per_bug_type[bt]
                        print(f"  📋 KS-only[{bt}]: {info}")
                        
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    # Summary
    print("\n" + "=" * 80)
    print(f"SUMMARY: {differentials}/{len(results)} tests showed differential")
    print(f"  Verdict diffs:      {sum(1 for r in results if r.verdict_diff)}")
    print(f"  Bug type diffs:     {sum(1 for r in results if r.bug_type_diff)}")
    print(f"  Per-bug-type diffs: {sum(1 for r in results if r.per_bug_type_diff)}")
    
    # Group by goal
    from collections import defaultdict
    by_goal = defaultdict(list)
    for r in results:
        by_goal[r.goal].append(r)
    
    for goal in sorted(by_goal.keys()):
        goal_results = by_goal[goal]
        goal_diffs = sum(1 for r in goal_results if r.has_differential)
        goal_name = {
            1: "BMC + Stochastic",
            2: "Local Safety Proofs",
            3: "Invariant Discovery",
            4: "Polynomial Barrier Synthesis", 
            5: "Abstraction-Refinement",
            6: "Compositional Reasoning",
            7: "Semantic Bug Types",
            99: "Paper Composition",
        }.get(goal, f"Goal {goal}")
        print(f"\n  GOAL {goal} ({goal_name}): {goal_diffs}/{len(goal_results)} differential")
        for r in goal_results:
            status = "DIFF" if r.has_differential else "SAME"
            detail = ""
            if r.verdict_diff:
                detail = f" (verdict: {r.ks_verdict} vs {r.no_ks_verdict})"
            elif r.bug_type_diff:
                detail = f" (bug_type: {r.ks_bug_type} vs {r.no_ks_bug_type})"
            elif r.per_bug_type_diff:
                ks_only = set(r.ks_per_bug_type.keys()) - set(r.no_ks_per_bug_type.keys())
                detail = f" (ks-only types: {ks_only})"
            print(f"    [{status}] {r.test_name}{detail}")
    
    # Save JSON
    if args.json:
        output = []
        for r in results:
            output.append({
                "test_name": r.test_name,
                "papers": r.papers,
                "goal": r.goal,
                "ks_verdict": r.ks_verdict,
                "no_ks_verdict": r.no_ks_verdict,
                "verdict_diff": r.verdict_diff,
                "ks_bug_type": r.ks_bug_type,
                "no_ks_bug_type": r.no_ks_bug_type,
                "bug_type_diff": r.bug_type_diff,
                "ks_per_bug_type": r.ks_per_bug_type,
                "no_ks_per_bug_type": r.no_ks_per_bug_type,
                "per_bug_type_diff": r.per_bug_type_diff,
                "ks_message": r.ks_message,
                "no_ks_message": r.no_ks_message,
                "ks_time_s": r.ks_time_s,
                "no_ks_time_s": r.no_ks_time_s,
                "ks_paths": r.ks_paths,
                "no_ks_paths": r.no_ks_paths,
                "has_differential": r.has_differential,
            })
        with open(args.json, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\nJSON results saved to {args.json}")


if __name__ == "__main__":
    main()
