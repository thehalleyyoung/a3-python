# PythonFromScratch

A static analysis tool for Python that finds **real bugs** in large codebases using bytecode analysis, barrier-certificate proofs, and Z3-backed symbolic execution.

Tested on Microsoft DeepSpeed (5,000+ functions) — found **6 confirmed true positives** including silent data corruption and unguarded division-by-zero bugs, while automatically proving 87.6% of candidates as false positives.

---

## Install

```bash
git clone https://github.com/halleyyoung/PythonFromScratch.git
cd PythonFromScratch
pip install -e .
```

Requires **Python ≥ 3.11** and **z3-solver** (installed automatically).

---

## Walkthrough: Analyze a Real Project

### 1. Clone a target repo

```bash
git clone https://github.com/microsoft/DeepSpeed.git external_tools/DeepSpeed
```

### 2. Run the analyzer

```bash
python3.11 -m pyfromscratch external_tools/DeepSpeed/deepspeed/
```

This runs the full pipeline automatically:

```
======================================================================
  PythonFromScratch — Full Project Analysis
  Target: external_tools/DeepSpeed/deepspeed
======================================================================

STEP 1: BUILDING CALL GRAPH
  Functions: 5003  (2.2s)

STEP 2: COMPUTING CRASH SUMMARIES
  Summaries: 5003  (329.4s)

STEP 3: BUILDING CODE OBJECTS FOR DSE
  Code objects: 5003  (0.0s)

STEP 4: BUG TYPE COVERAGE
    2928  NULL_PTR
     689  BOUNDS
     358  ASSERT_FAIL
     119  DIV_ZERO
      35  RUNTIME_ERROR
      ...

STEP 5: BARRIER CERTIFICATE + DSE ANALYSIS
  Total bug instances:     4613
  Fully guarded (guards):  3008
  Unguarded:               1605

  Barrier results (35.8s):
    Proven FP:   1031/1605
    Remaining:   574

STEP 6: DSE RESULTS
  DSE confirmed FP:    4
  DSE confirmed TP:    493

STEP 7: TRUE POSITIVE CANDIDATES
  Production code bugs:  571
  Test-only code bugs:   3

  TRUE POSITIVES (DSE-confirmed reachable):
    ⚠️ DIV_ZERO in utils.groups._ensure_divisibility
    ⚠️ DIV_ZERO in utils.timer.ThroughputTimer._is_report_boundary
    ⚠️ DIV_ZERO in inference.v2.inference_utils.ceil_div
    ...

SUMMARY
  Functions analysed:    5003
  Total bug instances:   4613
  Proven false positive: 4039 (87.6%)
  Remaining candidates:  574
  DSE-confirmed TPs:     493

  Results saved to results/deepspeed_results.pkl
```

### 3. Filter remaining false positives with Copilot

The analyzer's barrier certificates and DSE eliminate ~88% of false positives automatically. The remaining candidates include bugs that are technically reachable but may be guarded by framework invariants invisible at the bytecode level (e.g., "this parameter is always non-None because PyTorch guarantees it").

**Ask GitHub Copilot (or any LLM) to triage the remaining candidates:**

> Look at the output from `python3.11 -m pyfromscratch external_tools/DeepSpeed/deepspeed/`. For each remaining TP candidate, read the actual source code and callers to determine if it's a real bug or a false positive. Classify each as:
>
> - **REAL_BUG** — genuinely reachable crash from user input or config
> - **INTENTIONAL_GUARD** — deliberate `raise` (working as designed)
> - **FP_SELF** — attribute access on `self` (never None)
> - **FP_FRAMEWORK** — parameter guaranteed by framework (pytest, argparse, etc.)
> - **FP_INTERNAL** — parameter guaranteed by internal plumbing
>
> Write up the confirmed true positives in a markdown report.

This step typically reduces 500+ candidates down to **5–10 real bugs** with source-level evidence.

See [docs/TRUE_POSITIVE_ANALYSIS.md](docs/TRUE_POSITIVE_ANALYSIS.md) for our full DeepSpeed investigation.

---

## Single-File Analysis

```bash
# Analyze one file
python3.11 -m pyfromscratch myfile.py

# Security analysis — treats each function as an entry point with tainted params
python3.11 -m pyfromscratch myfile.py --functions

# Verbose output
python3.11 -m pyfromscratch myfile.py --verbose
```

**Exit codes:** `0` = SAFE, `1` = BUG found, `2` = UNKNOWN, `3` = error

---

## All Options

| Option | Description |
|--------|-------------|
| `--verbose` | Detailed output |
| `--functions` | Treat each function as a tainted entry point |
| `--all-functions` | Analyze ALL functions as entry points |
| `--interprocedural` | Cross-function taint analysis with call graph |
| `--entry-points NAME,...` | Specify entry point functions |
| `--min-confidence 0.0-1.0` | Filter bugs by confidence score |
| `--deduplicate` | Deduplicate findings by type + location |
| `--save-results PATH` | Custom output path (default: `results/<name>_results.pkl`) |
| `--context-depth N` | k-CFA context sensitivity (0, 1, 2, ...) |
| `--check-termination` | Detect non-terminating loops |
| `--synthesize-invariants` | Generate inductive loop invariants |
| `--no-concolic` | Pure symbolic analysis (no concrete execution) |

---

## Detected Bug Types

### Security Vulnerabilities (47 types)

**Injection**
- `SQL_INJECTION` — Unsanitized input in SQL queries
- `COMMAND_INJECTION` — Shell command injection
- `CODE_INJECTION` — Eval/exec with untrusted data
- `PATH_INJECTION` — Path traversal attacks
- `LDAP_INJECTION`, `XPATH_INJECTION`, `NOSQL_INJECTION`
- `REGEX_INJECTION` — ReDoS via user-controlled patterns
- `HEADER_INJECTION`, `COOKIE_INJECTION`

**Cross-Site Scripting (XSS)**
- `REFLECTED_XSS` — User input reflected in HTML output

**Server-Side Request Forgery**
- `SSRF` — Requests to user-controlled URLs
- `PARTIAL_SSRF` — Partial URL control

**Deserialization**
- `UNSAFE_DESERIALIZATION` — Pickle/YAML with untrusted data
- `XXE` — XML External Entity injection
- `XML_BOMB` — Billion laughs attack

**Sensitive Data**
- `CLEARTEXT_LOGGING` — Passwords/secrets in logs
- `CLEARTEXT_STORAGE` — Unencrypted sensitive data
- `HARDCODED_CREDENTIALS`

**Cryptography**
- `WEAK_CRYPTO` — MD5/SHA1 for security
- `WEAK_CRYPTO_KEY` — Insufficient key sizes
- `BROKEN_CRYPTO_ALGORITHM` — DES, RC4, etc.
- `INSECURE_PROTOCOL` — HTTP, FTP, Telnet

**Web Security**
- `URL_REDIRECT` — Open redirect vulnerabilities
- `CSRF_PROTECTION_DISABLED`
- `FLASK_DEBUG` — Debug mode in production
- `INSECURE_COOKIE` — Missing Secure/HttpOnly flags
- `JINJA2_AUTOESCAPE_FALSE`

**File System**
- `TAR_SLIP` — Tar extraction path traversal
- `INSECURE_TEMPORARY_FILE`
- `WEAK_FILE_PERMISSIONS`

**Network**
- `BIND_TO_ALL_INTERFACES` — 0.0.0.0 binding
- `MISSING_HOST_KEY_VALIDATION`
- `CERT_VALIDATION_DISABLED`

**Regex**
- `REDOS` — Catastrophic backtracking
- `POLYNOMIAL_REDOS`
- `BAD_TAG_FILTER`
- `INCOMPLETE_HOSTNAME_REGEXP`

### Core Bug Types (20 types)

- `DIV_ZERO` — Division by zero
- `NULL_PTR` — None dereference
- `BOUNDS` — Index out of bounds
- `TYPE_CONFUSION` — Type errors
- `ASSERT_FAIL` — Failed assertions
- `INTEGER_OVERFLOW`
- `NON_TERMINATION` — Infinite loops
- `MEMORY_LEAK`, `USE_AFTER_FREE`, `DOUBLE_FREE`
- `DATA_RACE`, `DEADLOCK`
- `INFO_LEAK`, `TIMING_CHANNEL`

## Examples

### Finding SQL Injection

```python
# vulnerable.py
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # BUG!
    return cursor.fetchone()
```

```bash
$ pyfromscratch vulnerable.py --functions
Analyzing: vulnerable.py

Function-level entry points: 1
  get_user: BUG
    SQL_INJECTION: Tainted value flows to SQL query at line 7

Total bugs found: 1
```

### Verifying Safe Code

```python
# safe.py
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # Safe!
    return cursor.fetchone()
```

```bash
$ pyfromscratch safe.py --functions
Analyzing: safe.py

Function-level entry points: 1
  get_user: SAFE

Total bugs found: 0
```

## How It Works

The analyzer runs a **7-step pipeline** on a project directory:

1. **Call Graph** — Builds a whole-program call graph from all `.py` files
2. **Crash Summaries** — Disassembles bytecode, finds unguarded divisions, None-dereferences, out-of-bounds accesses, etc.
3. **Code Objects** — Extracts Python code objects for symbolic execution
4. **Guard Detection** — Identifies bugs already protected by `if`, `try/except`, `assert`, `isinstance` checks
5. **Barrier Certificates** — 10 proof patterns (assume-guarantee, post-condition, refinement types, inductive invariants, control flow, dataflow, disjunctive, callee return-guarantee, validated params, DSE confirmation) attempt to formally prove each remaining bug is unreachable
6. **DSE (Z3)** — Dynamic symbolic execution confirms whether a concrete input can trigger each surviving bug
7. **Classification** — Separates production code from test code, reports true positive candidates

The tool produces one of three verdicts per bug:
- **FP (proven)** — barrier certificate or DSE proves the bug is unreachable
- **TP candidate** — no proof found; needs human/LLM triage
- **DSE-confirmed TP** — Z3 found a satisfying assignment that reaches the bug

## Architecture

```
pyfromscratch/
├── __main__.py   # python -m pyfromscratch entry point
├── cli.py        # CLI: single-file and project-directory analysis
├── analyzer.py   # Core analysis engine
├── frontend/     # Python loading, bytecode compilation
├── cfg/          # Control-flow graph + call graph construction
├── semantics/    # Symbolic bytecode execution, crash summaries
├── z3model/      # Z3 value/heap modeling
├── unsafe/       # Bug type predicates (67 types)
├── contracts/    # External call modeling, taint sources/sinks
├── dse/          # Concolic execution oracle (Z3-backed)
└── barriers/     # Barrier certificate synthesis (10 patterns)
```

## Docker

```bash
# Build
docker build -t pyfromscratch .

# Analyze a directory
docker run --rm -v $(pwd)/my_project:/target pyfromscratch /target

# Analyze a single file
docker run --rm -v $(pwd):/code pyfromscratch /code/myfile.py --functions
```

## Development

```bash
pytest                          # Run tests
pytest --cov=pyfromscratch      # With coverage
```

## License

See LICENSE file.
