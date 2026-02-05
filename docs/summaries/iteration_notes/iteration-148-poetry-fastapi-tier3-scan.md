# Iteration 148: Poetry and FastAPI Tier 3 Scan

## Date
2026-01-23 (Scan completed)

## Objective
Expand tier 3 diversity by scanning two additional specialist libraries:
- **poetry**: Dependency management and packaging tool
- **fastapi**: Modern async web framework

Compare with existing tier 3 repos (sqlalchemy, pydantic, mypy).

## Approach
1. Clone poetry and fastapi repositories
2. Run semantic analyzer on 100 Python files each (excluding tests)
3. Collect BUG/SAFE statistics
4. Compare with existing tier 3 bug rate profiles

## Results

### Poetry (Dependency Management)
- **Files analyzed**: 100
- **BUG**: 5 (5.0%)
- **SAFE**: 95 (95.0%)
- **UNKNOWN**: 0
- **ERROR**: 0

### FastAPI (Web Framework)
- **Files analyzed**: 100
- **BUG**: 34 (34.0%)
- **SAFE**: 66 (66.0%)
- **UNKNOWN**: 0
- **ERROR**: 0

## Tier 3 Comparison

All tier 3 repos now scanned (5 total):

| Repo | Bug Rate | Description | Validation Rate |
|------|----------|-------------|-----------------|
| **sqlalchemy** | 4% | ORM framework | 100% (iter 143) |
| **poetry** | 5% | Dependency management | *pending* |
| **fastapi** | 34% | Web framework | *pending* |
| **mypy** | 43% | Type checker | 100% (iter 147) |
| **pydantic** | 58% | Data validation | 96.6% (iter 145) |

### Bug Rate Spread: 4% to 58% (14.5x range)

## Key Findings

1. **Poetry has lowest tier 3 bug rate (5%)**:
   - Similar to SQLAlchemy (4%) - both mature, high-quality codebases
   - Low bug rate indicates strong engineering practices
   - Likely validates well (like SQLAlchemy)

2. **FastAPI in middle tier (34%)**:
   - Between low-bug (sqlalchemy/poetry) and high-bug (pydantic/mypy) categories
   - Similar to mypy (43%), lower than pydantic (58%)
   - Web framework patterns may differ from metaprogramming-heavy libraries

3. **Tier 3 diversity validated**:
   - ORM (sqlalchemy): 4%
   - Dependency management (poetry): 5%
   - Web framework (fastapi): 34%
   - Type checker (mypy): 43%
   - Data validation (pydantic): 58%
   - Wide range confirms diverse architectural patterns

4. **Zero UNKNOWN/ERROR results**:
   - Analyzer handles tier 3 code robustly
   - No opcode gaps in tier 3 specialist libraries
   - Phase 2 intraprocedural analysis working well

## Next Steps

1. **DSE validation** for poetry and fastapi:
   - poetry: expect high validation rate (similar to sqlalchemy)
   - fastapi: needs validation to assess FP rate
   
2. **Bug profile analysis**:
   - What bug types dominate in fastapi?
   - Compare web framework patterns to other tiers
   
3. **Comparative analysis**:
   - Module-init filtering effectiveness?
   - Import patterns?
   - Exception type distribution?

## Semantic Model Status

- **Test suite**: 1061 passed, 6 pre-existing closure failures (stable)
- **No regressions** from tier 3 expansion
- **Opcode coverage**: adequate for tier 3 specialist libraries
- **Phase 2**: successfully handles complex libraries

## Files Modified
- `scripts/poetry_fastapi_tier3_scan_iter148.py` (created)
- `results/public_repos/poetry_tier3_scan_iter148.json` (created)
- `results/public_repos/fastapi_tier3_scan_iter148.json` (created)
- `docs/notes/iteration-148-poetry-fastapi-tier3-scan.md` (this file)
- `State.json` (pending update)

## Barrier-Certificate Compliance

✓ No heuristics introduced - all results from semantic Z3 model
✓ Module-init filtering maintains over-approximation soundness
✓ BUG results are reachable paths (pending DSE validation)
✓ SAFE results have CEGIS-synthesized barrier certificates
✓ No text pattern matching - bytecode-based analysis only
