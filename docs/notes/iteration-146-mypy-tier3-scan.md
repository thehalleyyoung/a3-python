# Iteration 146: Mypy Tier 3 Scan

## Objective
Scan mypy (Python static type checker) as third tier 3 repository to continue evaluation of specialized Python libraries.

## Actions Taken
1. Cloned mypy repository from https://github.com/python/mypy.git
2. Created scan script `scripts/mypy_tier3_scan_iter146.py`
3. Scanned 100 Python files from mypy (excluding tests)
4. Analyzed bug type distribution

## Results

### Overall Metrics
- **Files analyzed**: 100
- **BUG**: 43 (43.0%)
- **SAFE**: 57 (57.0%)
- **UNKNOWN**: 0 (0.0%)
- **ERROR**: 0 (0.0%)

### Bug Type Breakdown
- **PANIC**: 15 (35% of bugs)
- **BOUNDS**: 14 (33% of bugs)
- **TYPE_CONFUSION**: 12 (28% of bugs)
- **NULL_PTR**: 2 (5% of bugs)

## Analysis

### Tier 3 Comparison
| Repo | Bug Rate | SAFE Rate | Primary Bug Type | Notable |
|------|----------|-----------|------------------|---------|
| SQLAlchemy (iter 142) | 4% | 96% | PANIC (75%) | Lowest tier 3 |
| Mypy (iter 146) | 43% | 57% | PANIC (35%), BOUNDS (33%) | Middle tier 3 |
| Pydantic (iter 144) | 58% | 41% | PANIC (90%) | Highest tier 3 |

### Key Findings

1. **Diverse Bug Profile**: Unlike Pydantic (90% PANIC) and SQLAlchemy (75% PANIC), mypy shows a more balanced distribution:
   - PANIC dominance reduced to 35%
   - BOUNDS and TYPE_CONFUSION are significant (33% and 28%)

2. **Moderate Bug Rate**: 43% positions mypy between SQLAlchemy (4%) and Pydantic (58%), suggesting moderate complexity or isolated-analysis challenges.

3. **BOUNDS Prominence**: 14 BOUNDS bugs (33%) is notably higher than other tier 3 repos. This may indicate:
   - Dict/list operations without bounds checks
   - Iterator protocol usage patterns
   - Index/key access patterns specific to compiler/type-checker code

4. **TYPE_CONFUSION**: 12 bugs (28%) suggests dynamic dispatch or protocol patterns that the analyzer flags.

5. **Zero UNKNOWN/ERROR**: Perfect analysis coverage - all files produced definitive BUG/SAFE results.

## Comparison Context

### Bug Rate Ranking (All Tiers)
1. SQLAlchemy (tier 3): 4%
2. Pandas (tier 2): 6%
3. Ansible (tier 2): 6%
4. Scikit-learn (tier 2): 6-7%
5. Numpy (tier 2): 8%
6. **Mypy (tier 3): 43%** ← New entry
7. Pydantic (tier 3): 58%

### Next Steps
1. **DSE Validation** (iteration 147): Validate mypy bugs with concrete execution to determine true positive rate
2. **Bug Pattern Analysis**: Investigate BOUNDS and TYPE_CONFUSION patterns specific to type checker/compiler code
3. **Comparison with Pydantic**: Both are metaprogramming-heavy libs - understand why mypy is lower (43% vs 58%)

## Test Suite Status
- **Passed**: 1061
- **Failed**: 6 (pre-existing closure failures)
- **Skipped**: 14
- **Xfailed**: 18
- **Status**: Stable ✓

## Artifacts
- Scan script: `scripts/mypy_tier3_scan_iter146.py`
- Results: `results/public_repos/mypy_tier3_scan_iter146.json`
- State.json updated: iteration 146, mypy added to tier3_metrics

## Soundness
- All bugs semantically justified (heap/transition/barrier model)
- No heuristics introduced
- Module-init filtering applied consistently
- Maintains Sem ⊆ R over-approximation property
