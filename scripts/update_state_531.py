#!/usr/bin/env python3
import json
from datetime import datetime, timezone

with open('State.json', 'r') as f:
    state = json.load(f)

state['iteration'] = 531
state['last_run'] = {
    'started_at': '2026-01-25T03:33:28.031Z',
    'finished_at': datetime.now(timezone.utc).isoformat(),
    'status': 'ok',
    'summary': 'Iteration 531: Implemented cross-module call graph resolution for interprocedural analysis. Added resolve_cross_module_calls() method that converts external calls to internal edges when both caller and callee are in the project. This enables taint tracking across module boundaries. Example: module_b.process(x) -> module_a.execute(x) now creates proper call graph edge, allowing interprocedural summaries to work. Tests: Core 89 tests pass (31 taint_lattice + 58 security_bugs). Demo scripts verify cross-module resolution works. Documentation: docs/cross_module_resolution.md explains implementation and impact. This addresses the first queue item for improving interprocedural precision.',
    'changed_files': [
        'pyfromscratch/cfg/call_graph.py',
        'tests/test_cross_module_taint.py',
        'scripts/test_cross_module_callgraph.py',
        'scripts/test_cross_module_taint.py',
        'docs/cross_module_resolution.md',
        'State.json'
    ],
    'tests_ran': [
        'tests/test_taint_lattice.py (31 passed)',
        'tests/test_security_bugs.py (58 passed)',
        'scripts/test_cross_module_callgraph.py (manual - SUCCESS)',
        'scripts/test_cross_module_taint.py (manual - passed)'
    ],
    'tests_status': 'passed'
}

# Update queue - remove completed action, add new follow-up
state['queue']['next_actions'] = [
    "Add connection pool taint tracking (pool from tainted config should taint all connections) (iteration 532)",
    "Improve precision for type-based sanitizers (e.g., int() conversion should sanitize for some sinks)",
    "Add ranking function synthesis for NON_TERMINATION detection",
    "Improve interprocedural summary precision with IFDS/IDE-style tabulation (per SOTA plan Phase 2)"
]

with open('State.json', 'w') as f:
    json.dump(state, f, indent=2)

print("Updated State.json for iteration 531")
