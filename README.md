# PythonFromScratch

A static analysis tool for Python that detects security vulnerabilities and bugs using symbolic execution and barrier-certificate proofs.

## Installation

### From source

```bash
git clone https://github.com/your-org/PythonFromScratch.git
cd PythonFromScratch
pip install -e .
```

### Using Docker

```bash
docker build -t pyfromscratch .
```

## Quick Start

```bash
# Analyze a single file
pyfromscratch myfile.py

# Security analysis with function-level entry points
pyfromscratch myfile.py --functions

# Interprocedural analysis of a project
pyfromscratch myproject/ --interprocedural
```

## Usage

### Basic Analysis

```bash
pyfromscratch <file.py> [options]
```

**Exit codes:**
- `0` = **SAFE** — verified with barrier certificate
- `1` = **BUG** — counterexample found
- `2` = **UNKNOWN** — neither proof nor counterexample
- `3` = Error (file not found, etc.)

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--verbose` | Show detailed analysis output |
| `--functions` | Analyze functions as entry points with tainted parameters |
| `--all-functions` | Analyze ALL functions as entry points |
| `--interprocedural` | Enable cross-function analysis with call graph |
| `--entry-points NAME,...` | Specify entry point functions (comma-separated) |
| `--min-confidence 0.0-1.0` | Filter bugs by confidence score |
| `--deduplicate` | Deduplicate findings by type + location |
| `--context-depth N` | k-CFA context sensitivity (0=insensitive, 1=1-CFA, etc.) |
| `--check-termination` | Detect non-terminating loops |
| `--synthesize-invariants` | Generate inductive loop invariants |
| `--no-concolic` | Pure symbolic analysis (no concrete execution) |

### Analysis Modes

#### 1. Module-Level Analysis (default)
Analyzes top-level code execution:
```bash
pyfromscratch script.py
```

#### 2. Function Entry Point Analysis
Treats each function as an entry point with untrusted (tainted) parameters — ideal for security analysis:
```bash
pyfromscratch app.py --functions
```

#### 3. Interprocedural Analysis
Follows data flow across function calls with call-graph construction:
```bash
pyfromscratch myproject/ --interprocedural --entry-points main,handle_request
```

### Docker Usage

```bash
# Analyze a file (mount your code to /target)
docker run --rm -v $(pwd):/target pyfromscratch /target/myfile.py

# With options
docker run --rm -v $(pwd):/target pyfromscratch /target/app.py --functions --verbose

# Interprocedural analysis of a directory
docker run --rm -v $(pwd)/myproject:/target pyfromscratch /target --interprocedural
```

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

1. **Frontend** — Compiles Python to bytecode, builds control-flow graphs
2. **Symbolic Execution** — Explores program paths with Z3 constraints
3. **Taint Tracking** — Traces untrusted data through the program
4. **Unsafe Predicates** — Checks if tainted data reaches dangerous sinks
5. **Barrier Synthesis** — Attempts to prove safety via inductive invariants

The tool produces one of three verdicts:
- **BUG**: Found a concrete path from source to sink
- **SAFE**: Proved no such path exists (barrier certificate)
- **UNKNOWN**: Could not determine either way

## Architecture

```
pyfromscratch/
├── frontend/     # Python loading, bytecode compilation
├── cfg/          # Control-flow graph construction
├── semantics/    # Symbolic bytecode execution
├── z3model/      # Z3 value/heap modeling
├── unsafe/       # Bug type predicates (67 types)
├── contracts/    # External call modeling, taint sources/sinks
├── dse/          # Concolic execution oracle
└── barriers/     # Barrier certificate synthesis
```

## Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=pyfromscratch

# Type checking
mypy pyfromscratch
```

## Requirements

- Python ≥ 3.11
- z3-solver ≥ 4.12.0

## License

See LICENSE file.
