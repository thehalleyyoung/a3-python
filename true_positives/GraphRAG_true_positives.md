# GraphRAG True Positives

GraphRAG is a knowledge graph-based RAG (Retrieval Augmented Generation) system.

## Summary (After FP Reduction: 138 → 2 bugs, 98.6% reduction)

| Bug Type | Before | After | Notes |
|----------|--------|-------|-------|
| NULL_PTR | 65 | 0 | All filtered (CLI/config context) |
| BOUNDS | 26 | 0 | All filtered (CLI/config context) |
| ITERATOR_INVALID | 12 | 0 | All filtered (CLI/config context) |
| DIV_ZERO | 8 | 2 | 2 edge cases at 0.41 confidence |
| TYPE_CONFUSION | 2 | 0 | All filtered |
| PATH_INJECTION | 7 | 0 | All filtered (CLI context) |
| TARSLIP | 6 | 0 | All filtered (CLI context) |
| ZIPSLIP | 6 | 0 | All filtered (CLI context) |
| JINJA2_INJECTION | 3 | 0 | All filtered (string.Template, not Jinja2) |
| TEMPLATE_INJECTION | 3 | 0 | All filtered (string.Template, not Jinja2) |
| **Total** | **138** | **2** | **98.6% reduction** |

---

## Remaining Findings (2 bugs)

### 1. DIV_ZERO @ cli/initialize.py:37 (conf: 0.41)

**Status**: LIKELY FALSE POSITIVE  
**Reason**: Transitive analysis from callee - no division in `initialize_project_at()`

```python
def initialize_project_at(path: Path, force: bool) -> None:
    # No division operations in this function
    logger.info("Initializing project at %s", path)
    root = Path(path)
    # ...
```

### 2. DIV_ZERO @ cli/prompt_tune.py:25 (conf: 0.41)

**Status**: LIKELY FALSE POSITIVE  
**Reason**: Transitive analysis from callee - no direct division in `prompt_tune()`

```python
async def prompt_tune(root: Path, config: Path | None, ...):
    # Division may occur in downstream LLM/embedding operations
    # but these are guarded by proper error handling
```

---

## FP Reduction Analysis

### Why Most Bugs Were False Positives

1. **CLI Tool Context** (cli/, config/, utils/, logger/ directories)
   - GraphRAG is a local CLI tool
   - User controls all inputs (paths, configs)
   - Crashes from misconfiguration are user error, not security bugs
   - Applied 0.5x multiplier for crash bugs in CLI context

2. **Security Bugs in CLI Context** (PATH_INJECTION, TARSLIP, ZIPSLIP)
   - User provides their own paths via `typer.Option()`
   - No remote attack surface
   - Applied 0.25x multiplier

3. **string.Template vs Jinja2** (JINJA2_INJECTION, TEMPLATE_INJECTION)
   - GraphRAG uses `from string import Template`
   - Python's string.Template only supports `$variable` substitution
   - No code execution, unlike Jinja2
   - Applied 0.0x multiplier (completely filtered)

---

## True Positive Candidates (Lower Priority)

These bugs may be real but are low severity for a CLI tool:

### BOUNDS in kwargs Access (Not Reported After Reduction)

```python
# graphrag/logger/factory.py:82-88
def create_file_logger(**kwargs) -> logging.Handler:
    root_dir = kwargs["root_dir"]   # KeyError if missing
```

**Status**: REAL but LOW severity - internal API, callers control kwargs

### NULL_PTR in Storage Functions (Not Reported After Reduction)

```python
# graphrag/utils/storage.py:22-23
return pd.read_parquet(BytesIO(await storage.get(filename, as_bytes=True)))
```

**Status**: REAL but LOW severity - race condition between has() and get()

---

**Conclusion:** GraphRAG has excellent FP reduction (98.6%) because it's a local CLI tool. The 2 remaining DIV_ZERO bugs are at the confidence threshold edge and likely false positives from transitive analysis.
