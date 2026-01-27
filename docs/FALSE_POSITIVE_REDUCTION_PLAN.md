# False Positive Reduction Plan

## Executive Summary

Based on analysis of 15+ Microsoft RISE repos (FLAML, Qlib, GraphRAG, DeepSpeed, Presidio, etc.) and PyGoat, we've identified recurring false positive patterns. This plan proposes **smarter testing** to systematically reduce FPs while maintaining high recall.

---

## Phase 1: Categorize Observed FP Patterns

### 1.1 Context-Insensitive FPs (Most Common)

| Pattern | Example | Root Cause | Solution |
|---------|---------|-----------|----------|
| **CLI Tool Sources** | `argparse`, `sys.argv`, `os.environ` | Local user input treated as untrusted | Add `is_cli_tool_context()` predicate |
| **Local Config Paths** | `config_path = Path(args.config)` | User-controlled paths are intentional | Check for `argparse`/`click` origin |
| **Self-Loading Pickle** | `pickle.load(self.checkpoint_file)` | User loads their own data | Track file provenance (created vs downloaded) |
| **Safe YAML Loaders** | `yaml.safe_load()`, `ruamel.yaml.YAML(typ='safe')` | Wrong loader recognition | Extend safe loader contracts |
| **Debug/Test Code** | Code in `test_*.py`, `debug_*.py` | Security irrelevant in tests | Skip or deprioritize test files |

### 1.2 Framework-Aware FPs

| Pattern | Example | Root Cause | Solution |
|---------|---------|-----------|----------|
| **Defense-in-Depth Mitigation** | `eval(parse_field())` where `parse_field` adds prefix | Sanitizer chain not tracked | Track multi-hop sanitization |
| **CLI Path Arguments** | Flask/FastAPI with `--config` arg | Web framework ≠ CLI tool | Detect application entry point |
| **Template Variables** | `Template(text).substitute(os.environ)` | Config templating is intentional | Recognize config patterns |

### 1.3 Semantic-Context FPs

| Pattern | Example | Root Cause | Solution |
|---------|---------|-----------|----------|
| **Error Handlers** | Code in `except:` blocks | Different threat model | Lower confidence for exception paths |
| **Logging Sinks** | `logger.debug(user_input)` | Debug logs vs production | Differentiate log levels |
| **Internal APIs** | Library internal functions | No external attack surface | Track API exposure |

---

## Phase 2: Smart Testing Infrastructure

### 2.1 Create FP Regression Test Suite

```
tests/
├── fp_regression/
│   ├── cli_tool_patterns/
│   │   ├── argparse_path_injection.py    # Should NOT flag
│   │   ├── click_file_open.py            # Should NOT flag
│   │   └── test_cli_patterns.py
│   ├── safe_loader_patterns/
│   │   ├── yaml_safe_load.py             # Should NOT flag
│   │   ├── ruamel_safe.py                # Should NOT flag
│   │   └── test_yaml_patterns.py
│   ├── self_data_patterns/
│   │   ├── load_own_checkpoint.py        # Should NOT flag (or LOW)
│   │   ├── save_then_load.py             # Should NOT flag
│   │   └── test_self_data.py
│   ├── defense_in_depth/
│   │   ├── operator_prefix_eval.py       # Should be LOW (Qlib pattern)
│   │   ├── allowlist_before_exec.py      # Should be LOW
│   │   └── test_mitigation_chains.py
│   └── framework_patterns/
│       ├── flask_cli_app.py              # Should NOT flag CLI paths
│       ├── django_admin_command.py       # Should NOT flag
│       └── test_framework_context.py
```

### 2.2 Implement Repo-Wide FP Tracker

Create `fp_tracker.json`:
```json
{
  "repos": {
    "FLAML": {
      "total_findings": 12,
      "true_positives": 5,
      "false_positives": 7,
      "fp_categories": {
        "cli_path": 3,
        "self_pickle": 2,
        "test_code": 2
      }
    },
    "Qlib": {
      "total_findings": 20,
      "true_positives": 3,
      "false_positives": 17,
      "fp_categories": {
        "operator_prefix_eval": 5,
        "cli_path": 8,
        "safe_yaml": 4
      }
    }
  },
  "aggregate": {
    "precision": 0.28,
    "target_precision": 0.80
  }
}
```

### 2.3 Golden File Testing

For each repo, create expected output:
```
tests/golden/
├── FLAML_expected.json
├── Qlib_expected.json
├── GraphRAG_expected.json
└── ...
```

Compare actual vs expected, flag precision regression.

---

## Phase 3: Detector Improvements

### 3.1 Add Context Predicates

```python
# In confidence_scoring.py

def is_cli_tool_context(source_label: TaintLabel) -> bool:
    """Detect if taint comes from CLI argument parsing."""
    cli_sources = {
        SourceType.ARGPARSE,
        SourceType.CLICK,
        SourceType.SYS_ARGV,
        SourceType.ENV_VAR,  # Often CLI-like
    }
    return any(s.source_type in cli_sources for s in source_label.sources)

def is_self_data_flow(source_label: TaintLabel, sink_path: str) -> bool:
    """Detect if data was created and loaded by the same codebase."""
    # If source is a file written by a local save() call, likely safe
    for source in source_label.sources:
        if source.source_type == SourceType.FILE_CONTENT:
            # Check if file was written by same codebase
            # (requires interprocedural def-use tracking)
            pass
    return False

def has_defense_in_depth(call_chain: List[Call]) -> bool:
    """Detect if mitigation functions exist in call chain."""
    mitigation_patterns = [
        "sanitize", "validate", "filter", "escape", "quote",
        "parse_field",  # Qlib's operator prefix
        "allowlist", "whitelist", "safe_",
    ]
    for call in call_chain:
        func_name = call.func_name.lower()
        if any(pat in func_name for pat in mitigation_patterns):
            return True
    return False
```

### 3.2 Add Confidence Adjustments

```python
def adjust_confidence_for_context(
    base_confidence: float,
    is_cli: bool,
    is_test_file: bool,
    has_mitigation: bool,
    source_is_self_data: bool,
) -> float:
    """Apply context-aware confidence adjustments."""
    
    confidence = base_confidence
    
    # CLI context: Lower confidence for path/file ops
    if is_cli:
        confidence *= 0.3  # 70% reduction
    
    # Test files: Much lower priority
    if is_test_file:
        confidence *= 0.2  # 80% reduction
    
    # Defense-in-depth: Acknowledge mitigation
    if has_mitigation:
        confidence *= 0.4  # 60% reduction
    
    # Self-data: User loads their own data
    if source_is_self_data:
        confidence *= 0.3  # 70% reduction
    
    return confidence
```

### 3.3 Add Loader-Specific Contracts

```python
# In contracts/security_lattice.py

SAFE_YAML_LOADERS = {
    "yaml.safe_load": True,
    "yaml.safe_load_all": True,
    "ruamel.yaml.YAML": {
        "typ": {"safe", "rt", "pure"}  # Only 'safe' and 'rt' are safe
    },
    "strictyaml.load": True,
}

def is_safe_yaml_call(call: Call) -> bool:
    """Check if YAML loading is done safely."""
    if call.func_name == "ruamel.yaml.YAML":
        typ_arg = call.kwargs.get("typ", "rt")  # default is 'rt' (round-trip)
        return typ_arg in {"safe", "rt"}
    return call.func_name in SAFE_YAML_LOADERS
```

---

## Phase 4: Automated Validation Pipeline

### 4.1 CI Pipeline for FP Tracking

```yaml
# .github/workflows/fp_validation.yml
name: FP Validation

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run FP Regression Tests
        run: |
          python -m pytest tests/fp_regression/ -v
      
      - name: Run on Real Repos
        run: |
          python scripts/scan_all_repos.py --output results/
      
      - name: Check Precision Threshold
        run: |
          python scripts/check_precision.py --min-precision 0.75
```

### 4.2 Weekly Regression on Real Repos

```python
# scripts/weekly_validation.py

VALIDATION_REPOS = [
    "microsoft/FLAML",
    "microsoft/qlib", 
    "microsoft/graphrag",
    "microsoft/DeepSpeed",
    "microsoft/presidio",
    # ... etc
]

def run_weekly_validation():
    results = {}
    for repo in VALIDATION_REPOS:
        findings = analyze_repo(repo)
        tp, fp = triage_findings(findings)  # Uses heuristics + cached labels
        results[repo] = {
            "total": len(findings),
            "tp": tp,
            "fp": fp,
            "precision": tp / len(findings) if findings else 1.0
        }
    
    save_results("weekly_validation_results.json", results)
    check_regression(results)
```

---

## Phase 5: Confidence Threshold Tuning

### 5.1 Per-Bug-Type Thresholds

| Bug Type | Default Threshold | CLI Context | Test Files |
|----------|------------------|-------------|------------|
| SQL_INJECTION | 0.60 | 0.40 | 0.20 |
| COMMAND_INJECTION | 0.60 | 0.30 | 0.20 |
| PATH_INJECTION | 0.60 | 0.20 | 0.10 |
| CODE_INJECTION | 0.70 | 0.40 | 0.20 |
| PICKLE_INJECTION | 0.50 | 0.20 | 0.10 |
| CLEARTEXT_LOGGING | 0.50 | 0.30 | 0.10 |

### 5.2 Reporting Tiers

```python
class ReportingTier(Enum):
    CRITICAL = "critical"     # confidence >= 0.80, always report
    HIGH = "high"             # confidence >= 0.60, report by default
    MEDIUM = "medium"         # confidence >= 0.40, report with flag
    LOW = "low"               # confidence >= 0.20, suppressed by default
    INFORMATIONAL = "info"    # confidence < 0.20, never report
```

---

## Phase 6: Implementation Roadmap

### Week 1-2: Foundation
- [ ] Create FP regression test suite structure
- [ ] Add `is_cli_tool_context()` predicate
- [ ] Add safe YAML loader contracts
- [ ] Create `fp_tracker.json` schema

### Week 3-4: Context Detection
- [ ] Implement `has_defense_in_depth()` for call chains
- [ ] Add test file detection (`is_test_file()`)
- [ ] Add `adjust_confidence_for_context()`
- [ ] Create golden files for 5 repos

### Week 5-6: Validation
- [ ] Run on all 15 MS RISE repos
- [ ] Track precision improvement
- [ ] Tune thresholds based on results
- [ ] Document remaining FP categories

### Week 7-8: Integration
- [ ] Add CI pipeline
- [ ] Weekly validation automation
- [ ] Update documentation
- [ ] Release with improved precision

---

## Success Metrics

| Metric | Current | Target | Measurement |
|--------|---------|--------|-------------|
| Precision (PyGoat) | 85% | 95% | TP / (TP + FP) |
| Precision (MS RISE avg) | ~30% | 75% | Avg across repos |
| CLI Tool FP Rate | High | <10% | FP from argparse/click |
| Safe Loader FP Rate | High | 0% | FP from safe_load |
| Test File Noise | High | 0 reports | No reports for test files |

---

## Appendix: Observed FP Categories by Repo

| Repo | Most Common FP | Second Most Common |
|------|---------------|-------------------|
| FLAML | pickle (self-data) | CLI paths |
| Qlib | operator prefix eval | safe YAML |
| GraphRAG | CLI config paths | optional field access |
| DeepSpeed | checkpoint loading (industry-wide) | - |
| Presidio | regex DoS (documented) | - |
| LightGBM | CLI paths | subprocess (controlled) |
| Guidance | - | - |
| RESTler | - | - |
| RDAgent | - | - |
| ONNXRuntime | subprocess (build scripts) | - |
| SemanticKernel | - | - |
| DebugPy | - | - |
| PromptFlow | CLI paths | - |
| MSTICPY | - | - |
| Counterfit | - | - |

---

## Summary

The key insight is that **context matters more than pattern matching**:

1. **CLI tools** have a different threat model than web apps
2. **Self-data loading** (user's own checkpoints) is different from loading untrusted data
3. **Defense-in-depth** mitigations (operator prefixes, allowlists) reduce risk even if not perfect
4. **Test files** should be deprioritized or skipped entirely
5. **Safe loaders** (`yaml.safe_load`) should never be flagged

By implementing these context-aware adjustments, we can reduce FP rate from ~70% to ~25% while maintaining high recall for actual vulnerabilities.
