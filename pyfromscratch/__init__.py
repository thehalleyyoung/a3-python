"""
PythonFromScratch: Stateful, Continuous Python Semantics + Barrier-Certificate Verifier

A program analysis toolchain that produces:
1. BUG: model-checked reachable unsafe state with concrete counterexample trace
2. SAFE: proof (barrier certificate / inductive invariant) of unreachability
3. UNKNOWN: neither proof nor counterexample

No heuristics. Grounded in Python→Z3 heap/transition/barrier model.
"""

__version__ = "0.1.0"
