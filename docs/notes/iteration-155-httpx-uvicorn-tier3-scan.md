# Iteration 155: httpx and uvicorn Tier 3 Scan

**Date**: 2026-01-23  
**Iteration**: 155  
**Phase**: PUBLIC_REPO_EVAL (Tier 3 diversity expansion)

## Objective
Expand tier 3 diversity by scanning httpx (HTTP client) and uvicorn (ASGI server), continuing the diversity expansion pattern from existing tier 3 repos.

## Repositories Scanned

### httpx
- **Description**: HTTP client library with HTTP/2 support
- **Files Analyzed**: 23
- **Bug Rate**: 43.5% (10 bugs)
- **Safe Rate**: 56.5% (13 safe)
- **Unknown**: 0
- **Error**: 0
- **Results**: `results/public_repos/httpx_tier3_scan_iter155.json`

### uvicorn
- **Description**: Lightning-fast ASGI server implementation
- **Files Analyzed**: 41
- **Bug Rate**: 41.5% (17 bugs)
- **Safe Rate**: 58.5% (24 safe)
- **Unknown**: 0
- **Error**: 0
- **Results**: `results/public_repos/uvicorn_tier3_scan_iter155.json`

## Summary Statistics

### Combined Scan Results
- **Total Files**: 64 (httpx: 23, uvicorn: 41)
- **Total Bugs**: 27 (10 + 17)
- **Total Safe**: 37 (13 + 24)
- **Combined Bug Rate**: 42.2%
- **Combined Safe Rate**: 57.8%
- **Zero Errors**: Perfect analyzer stability

### Tier 3 Bug Rate Ranking (7 repos)
1. sqlalchemy: 4.0% (lowest)
2. poetry: 5.0%
3. fastapi: 34.0%
4. uvicorn: 41.5% ← **NEW**
5. mypy: 43.0%
6. httpx: 43.5% ← **NEW**
7. pydantic: 58.0% (highest)

### Bug Rate Distribution
- **Low (4-5%)**: sqlalchemy, poetry (infrastructure/tooling)
- **Medium (34-43%)**: fastapi, uvicorn, mypy, httpx (application frameworks/clients)
- **High (58%)**: pydantic (metaprogramming-heavy)

## Key Observations

### 1. Bug Rate Consistency
- **httpx (43.5%)** and **uvicorn (41.5%)** cluster with mypy (43%) in the medium range
- Both are significantly higher than infrastructure tooling (sqlalchemy 4%, poetry 5%)
- Both are lower than metaprogramming-heavy pydantic (58%)
- This aligns with application-framework complexity patterns

### 2. Diversity Validation
- **httpx**: HTTP client (network protocol layer)
- **uvicorn**: ASGI server (async server layer)
- Together with existing tier 3:
  - ORM: sqlalchemy
  - Data validation: pydantic
  - Type checker: mypy
  - Dependency mgmt: poetry
  - Web framework: fastapi
  - HTTP client: httpx ← new
  - ASGI server: uvicorn ← new

Tier 3 now spans 7 distinct architectural domains.

### 3. Analyzer Stability
- **Zero errors** across 64 files
- **Zero unknown** results
- Perfect classification (BUG/SAFE only)
- Demonstrates robust opcode coverage and semantic model stability

### 4. Network/Protocol Layer Coverage
- httpx + uvicorn represent complementary ends of HTTP stack:
  - httpx: client-side HTTP/HTTP2
  - uvicorn: server-side ASGI
- Both in same bug rate cluster (41-43%) suggests consistent complexity

## Comparison with Existing Tier 3

| Repo       | Bug Rate | Validation | Domain               | New? |
|------------|----------|------------|----------------------|------|
| sqlalchemy | 4%       | 100%       | ORM/database         |      |
| poetry     | 5%       | 80%        | Dependency mgmt      |      |
| fastapi    | 34%      | 100%       | Web framework        |      |
| uvicorn    | 41.5%    | TBD        | ASGI server          | ✓    |
| mypy       | 43%      | 100%       | Type checker         |      |
| httpx      | 43.5%    | TBD        | HTTP client          | ✓    |
| pydantic   | 58%      | 96.6%      | Data validation      |      |

### Overall Tier 3 Metrics (Pre-Validation)
- **Total Repos**: 7
- **Validated Repos**: 5
- **Pending Validation**: 2 (httpx, uvicorn) ← next iteration
- **Overall Validation Rate**: 97.9% (141/144 pre-validation)

## Next Steps

### Immediate (Iteration 156)
1. **DSE validation for httpx**: Validate 10 bugs, extract concrete repros
2. **DSE validation for uvicorn**: Validate 17 bugs, extract concrete repros
3. **Comparative analysis**: Compare validation rates with mypy (same bug rate tier)

### Follow-Up
4. **Bug type profiling**: Extract bug type breakdown (PANIC/BOUNDS/TYPE_CONFUSION/NULL_PTR) for httpx and uvicorn
5. **Module-init analysis**: Determine module-init vs function-body bug distribution
6. **Exception analysis**: Profile exception types (ImportError, NameError, TypeError, etc.)
7. **Network-layer pattern analysis**: Identify network/protocol-specific bug patterns

## Technical Notes

### Scan Configuration
- **Max files per repo**: 100
- **Timeout per file**: 30 seconds
- **Exclusions**: tests, __pycache__, examples
- **Python version**: 3.14
- **Analyzer phase**: Intraprocedural phase 3 (recursion + ranking functions)

### File Distribution
- httpx: 23 files (smaller, focused library)
- uvicorn: 41 files (larger, protocol implementations)
- Total tier 3: ~700 files across 7 repos

## Soundness and Anti-Cheating

### Semantic Fidelity
- All results grounded in Z3 symbolic model
- No heuristic-based detection
- Unknown calls modeled as sound over-approximations
- Module-init filtering maintains soundness (only removes module-scope bugs per policy)

### Pending Validation
- httpx: 10 bugs need DSE validation (concrete witness extraction)
- uvicorn: 17 bugs need DSE validation
- Expected validation rate: 90-100% based on tier 3 history (97.9% overall)

## State Updates

### Added to State.json
- httpx and uvicorn to `progress.evaluation.public_repos.cloned`
- httpx and uvicorn scans to `progress.evaluation.public_repos.scanned`
- Updated tier 3 metrics summary
- Queued DSE validation for next iteration

### Knowledge Artifacts
- Scan results: `results/public_repos/httpx_tier3_scan_iter155.json`
- Scan results: `results/public_repos/uvicorn_tier3_scan_iter155.json`
- Scan log: `results/iteration_155_scan.log`
- This summary: `docs/notes/iteration-155-httpx-uvicorn-tier3-scan.md`
