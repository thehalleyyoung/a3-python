# Iteration 38: Public Repository Evaluation Infrastructure

## Objective
Create reproducible public repository evaluation infrastructure for real-world validation of all 20 bug types.

## What was implemented

### 1. Reproducible Repository List (`pyfromscratch/evaluation/repo_list.py`)
- 15 popular, well-maintained Python repositories organized in 3 tiers
- **Tier 1** (5 repos): Small to medium projects (click, flask, requests, pytest, rich)
- **Tier 2** (5 repos): Larger, complex projects (django, scikit-learn, ansible, httpie, black)
- **Tier 3** (5 repos): Specialist projects (mypy, poetry, pydantic, sqlalchemy, fastapi)
- Selection criteria:
  - GitHub stars > 1000
  - Diverse domains (web, ML, CLI, testing, data validation)
  - Actively maintained
  - Primarily Python (not binding-heavy)

### 2. Scanning Pipeline (`pyfromscratch/evaluation/scanner.py`)
- `RepoScanner` class orchestrates end-to-end scanning
- Workflow:
  1. Clone repo (or skip if already cloned) using `git clone --depth 1`
  2. Discover Python files (excludes venv, build dirs, large generated files)
  3. Analyze each file with all 20 bug detectors
  4. Collect findings: BUG (with trace), SAFE (with proof), UNKNOWN, ERROR
  5. Save results to JSON for triage
- Safety features:
  - Error handling per file (failures don't stop scan)
  - Size limits (skip files > 500KB)
  - File count limits (configurable max_files per repo)
  - Timeout protection

### 3. Analysis Interface Extension (`pyfromscratch/analyzer.py`)
- New `analyze_file(filepath, source_code)` function for batch analysis
- Returns `FileAnalysisResult` with:
  - `bugs`: List of BUG findings with witness traces
  - `safe_proofs`: List of SAFE proofs with barrier certificates
  - `unknowns`: List of UNKNOWN results
  - `errors`: Analysis errors
- Supports multi-bug-type analysis (foundation for scanning all 20 types per file)

### 4. CLI Script (`scripts/run_public_eval.py`)
- Commands:
  - `list`: Show all available repositories
  - `tier <1|2|3>`: Scan all repos in a tier
  - `repo <name>`: Scan a specific repository
- Configurable max files per repo (default: 50)
- Summary reports with finding counts

## Design principles (anti-cheating compliance)

1. **No heuristics in triage**: Findings must have semantic witness traces or proofs
2. **Over-approximation soundness**: Unknown calls are conservatively modeled
3. **Error isolation**: Per-file failures don't compromise scan integrity
4. **Reproducibility**: Fixed repo list with version control (git clone)
5. **Transparency**: All results saved to JSON with full traces

## Next steps (Phase: PUBLIC_REPO_EVAL)

1. ✅ Create reproducible repo list
2. ✅ Build scanning pipeline
3. ⏭️ Run on tier 1 repos (5 repos, ~50 files each)
4. ⏭️ Triage findings: validate BUG traces, check SAFE proofs
5. ⏭️ Track false positives/negatives in State.json
6. ⏭️ Refine semantics/contracts based on real-world findings

## Testing
- Dry run: `python scripts/run_public_eval.py list` succeeds
- Infrastructure ready for first batch scan

## Files changed
- `pyfromscratch/evaluation/__init__.py` (new)
- `pyfromscratch/evaluation/repo_list.py` (new)
- `pyfromscratch/evaluation/scanner.py` (new)
- `pyfromscratch/analyzer.py` (extended for batch analysis)
- `scripts/run_public_eval.py` (new CLI)
- `docs/notes/iteration-38-public-eval-infra.md` (this file)
