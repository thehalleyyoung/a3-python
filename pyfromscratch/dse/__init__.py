"""
DSE (Dynamic Symbolic Execution) as a refinement oracle.

Concolic execution that attempts to realize symbolic traces via concrete execution.
Never used to prove infeasibility (under-approximate oracle only).
"""

from .concolic import ConcreteExecutor, TraceValidator, DSEResult
from .selective_concolic import SelectiveConcolicExecutor, SelectiveConcolicTrace
from .hybrid import ConcolicReplayOracle
from .lockstep import run_lockstep, LockstepResult

__all__ = [
    "ConcreteExecutor",
    "TraceValidator",
    "DSEResult",
    "SelectiveConcolicExecutor",
    "SelectiveConcolicTrace",
    "ConcolicReplayOracle",
    "run_lockstep",
    "LockstepResult",
]
