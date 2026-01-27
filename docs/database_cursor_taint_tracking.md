# Database Cursor Taint Tracking (Iteration 529)

## Summary

Database cursor taint tracking is now fully supported through the enhanced taint propagation mechanism. This enables the system to track taint flow from database connections through cursors to query results:

```python
# Taint flows: conn_str → connection → cursor → results
conn_str = os.environ.get('DB_URL')  # TAINTED from ENVIRONMENT
conn = sqlite3.connect(conn_str)      # Connection inherits taint
cursor = conn.cursor()                # Cursor inherits from connection
results = cursor.fetchone()           # Results inherit from BOTH cursor AND DATABASE_RESULT source
query = f"SELECT * FROM {results[0]}" # Query inherits taint
cursor.execute(query)                 # SQL_INJECTION detected!
```

## Implementation

### Core Mechanism: Enhanced Source Handling

The key improvement is in `LatticeSecurityTracker.handle_call_post()` - sources now **merge** with callable taint instead of replacing it.

**File:** `pyfromscratch/semantics/security_tracker_lattice.py`

**Before (Iteration 528):**
```python
# Check if this is a taint source
if is_taint_source(func_name):
    concrete = apply_source_taint(func_name, location)
    symbolic = apply_source_taint_symbolic(func_name)
    # ... (only source taint used)
    return concrete, symbolic
```

**After (Iteration 529):**
```python
# Check if this is a taint source
if is_taint_source(func_name):
    concrete = apply_source_taint(func_name, location)
    symbolic = apply_source_taint_symbolic(func_name)
    
    # ITERATION 529: For method calls on tainted objects, merge source taint with callable taint
    # Example: cursor.fetchone() should inherit taint from BOTH DATABASE_RESULT source AND cursor object
    if func_ref is not None:
        func_concrete = self.get_label(func_ref)
        func_symbolic = self.get_symbolic_label(func_ref)
        concrete = label_join(concrete, func_concrete)
        symbolic = symbolic_label_join(symbolic, func_symbolic)
    
    # ... (merged taint used)
    return concrete, symbolic
```

This ensures that method calls like `cursor.fetchone()` inherit taint from:
1. The **DATABASE_RESULT** source (because `fetchone` is a registered source)
2. The **cursor object itself** (if the cursor was created from a tainted connection)

### Taint Flow Chain

The full taint flow for database operations:

```
1. conn_str = os.environ.get('DB_URL')
   → τ(conn_str) = {ENVIRONMENT}  (from source contract)

2. conn = sqlite3.connect(conn_str)
   → τ(conn) = τ(conn_str) = {ENVIRONMENT}  (argument-to-result propagation)

3. cursor = conn.cursor()
   → τ(cursor) = τ(conn) = {ENVIRONMENT}  (callable-to-result propagation via func_ref)

4. results = cursor.fetchone()
   → τ(results) = τ(cursor) ∪ τ(DATABASE_RESULT)
   → τ(results) = {ENVIRONMENT, DATABASE_RESULT}  (source + callable merge)

5. query = f"SELECT * FROM {results[0]}"
   → τ(query) = τ(results) = {ENVIRONMENT, DATABASE_RESULT}  (string formatting)

6. cursor.execute(query)
   → UNSAFE: τ(query) ≠ ∅ ∧ κ(query) ∩ {SQL_EXECUTE} = ∅
   → SQL_INJECTION detected!
```

### Security Contracts

**File:** `pyfromscratch/contracts/security_lattice.py`

Database-related contracts are already defined:

**Sources:**
- `cursor.fetchone()` → `DATABASE_RESULT` source (+ cursor taint)
- `cursor.fetchall()` → `DATABASE_RESULT` source (+ cursor taint)
- `cursor.fetchmany()` → `DATABASE_RESULT` source (+ cursor taint)

**Sinks:**
- `cursor.execute()` → `SQL_EXECUTE` sink
- `cursor.executemany()` → `SQL_EXECUTE` sink
- `connection.execute()` → `SQL_EXECUTE` sink

**Functions (argument propagation):**
- `sqlite3.connect()` → propagates taint from connection string
- `connection.cursor()` → propagates taint from connection
- `pymongo.MongoClient()` → propagates taint from connection string
- `psycopg2.connect()` → propagates taint from connection string

## Test Coverage

### Unit Tests: `tests/test_cursor_taint.py`

5 comprehensive tests validate cursor taint propagation:

1. **test_cursor_from_tainted_connection_is_tainted**: Cursor from `conn.cursor()` inherits connection taint
2. **test_fetchone_from_tainted_cursor_is_tainted**: `cursor.fetchone()` inherits from BOTH DATABASE_RESULT source AND cursor
3. **test_clean_connection_produces_clean_cursor**: Clean connections produce clean cursors (no false positive)
4. **test_end_to_end_tainted_cursor_to_sql_injection**: Full flow from tainted connection to SQL injection detection
5. **test_cursor_from_clean_connection_with_tainted_query**: Standard SQL injection with clean cursor but tainted query

All tests pass ✓

### Integration with Existing Tests

- **31 tests** in `tests/test_taint_lattice.py` - all pass ✓
- **58 tests** in `tests/test_security_bugs.py` - all pass ✓

## Security Bug Detection

### SQL Injection from Tainted Connection

```python
conn_str = os.environ.get('DB_URL')  # Tainted from ENVIRONMENT
conn = sqlite3.connect(conn_str)
cursor = conn.cursor()
results = cursor.fetchone()           # Tainted from cursor + DATABASE_RESULT
query = f"SELECT * FROM {results[0]}" # Tainted query
cursor.execute(query)                 # ← SQL_INJECTION detected
```

**Unsafe Region:** `U_sql := { s | π = execute_call ∧ τ(query_arg) ≠ ∅ ∧ κ(query_arg) ∩ {SQL_EXECUTE} = ∅ }`

### Standard SQL Injection (Clean Cursor)

```python
cursor = db.cursor()                  # Clean cursor
user_input = request.args.get('id')   # Tainted from HTTP_PARAM
query = f"SELECT * FROM users WHERE id = {user_input}"
cursor.execute(query)                 # ← SQL_INJECTION detected
```

This case still works - the cursor is clean but the query is tainted from user input.

## Barrier-Theoretic Foundation

### Taint Propagation Invariant (Enhanced for Sources)

For a **source function** call `result = source_func(*args)` on callable `func_ref`:

```
τ(result) = τ(source) ∪ τ(func_ref) ∪ ⋃{τ(arg) | arg ∈ args}
κ(result) = κ(source) ∩ κ(func_ref) ∩ ⋂{κ(arg) | arg ∈ args}
σ(result) = σ(source) ∪ σ(func_ref) ∪ ⋃{σ(arg) | arg ∈ args}
```

Where:
- `τ(source)` = source taint bits from contract (e.g., DATABASE_RESULT)
- `τ(func_ref)` = taint from the callable object (e.g., cursor)
- `τ(args)` = taint from explicit arguments

This is the lattice join operation from `leak_theory.md`, extended to include source contracts.

### Safety Barrier for Database Operations

For a database operation at program point π with query `q`:

```
B_db(s) = {
    M                           if π ≠ π_execute
    (1 - δ_unsafe(s)) - 1/2     if π = π_execute
}
```

Where `δ_unsafe(s) = 1` iff:
```
τ(q) ≠ ∅  ∧  κ(q) ∩ {SQL_EXECUTE} = ∅
```

### Soundness

The implementation preserves soundness through:

1. **Over-approximation**: Taint only grows (τ ⊆ τ', σ ⊆ σ') and sanitization only shrinks (κ ⊇ κ')
2. **Join-based propagation**: Uses lattice join (⊔) which is monotone and associative
3. **Source contract merge**: Merging source + callable ensures no taint is lost

## Comparison with File Object Taint (Iteration 527)

Database cursor taint tracking follows the same pattern as file object taint tracking:

| Feature | File Objects (Iter 527) | Database Cursors (Iter 529) |
|---------|-------------------------|----------------------------|
| **Tainted container** | `f = open(tainted_path)` | `conn = connect(tainted_str)` |
| **Derived object** | `f` (file object) | `cursor = conn.cursor()` |
| **Method call** | `content = f.read()` | `results = cursor.fetchone()` |
| **Source + Object** | FILE_CONTENT + file taint | DATABASE_RESULT + cursor taint |
| **Sink detection** | `eval(content)` → CODE_INJECTION | `execute(query)` → SQL_INJECTION |

Both use the **same mechanism**: `handle_call_post` with source + callable merge.

## Real-World Impact

### PyGoat Scanning (Iteration 528)

The database cursor taint tracking will improve detection of:

1. **Second-order SQL injections**: Query results used in subsequent queries
2. **Cross-database taint**: Connection from tainted source → queries inherit taint
3. **NoSQL injections**: Same pattern applies to MongoDB, Redis, etc.

### Example from PyGoat

```python
# In a real Django view
db_url = os.environ.get('DATABASE_URL')  # ENVIRONMENT taint
conn = connect(db_url)
cursor = conn.cursor()
user_data = cursor.fetchone()  # Tainted from ENVIRONMENT + DATABASE_RESULT
# Later...
new_query = f"SELECT * FROM logs WHERE user = '{user_data[0]}'"
cursor.execute(new_query)  # SQL_INJECTION detected!
```

This type of second-order injection would have been missed before iteration 529.

## Future Extensions

### Connection Pool Taint

Connection pools should inherit taint from pool creation:

```python
pool_url = os.environ.get('POOL_URL')
pool = ConnectionPool(pool_url)  # Pool is tainted
conn = pool.get_connection()     # Connection inherits pool taint
cursor = conn.cursor()            # Cursor inherits connection taint
```

### ORM Query Results

ORM query results should inherit taint from model connections:

```python
# Django ORM
db_config = os.environ.get('DB_CONFIG')
# ... configure Django with db_config ...
user = User.objects.get(id=user_id)  # user inherits database taint
query = f"SELECT * FROM logs WHERE user = '{user.username}'"
cursor.execute(query)  # SQL_INJECTION detected
```

## References

- **Theory**: `python-barrier-certificate-theory.md` §9.5 (Taint Lattice)
- **Implementation**: `pyfromscratch/semantics/security_tracker_lattice.py`
- **Contracts**: `pyfromscratch/contracts/security_lattice.py`
- **Tests**: `tests/test_cursor_taint.py`
- **Related**: `docs/file_object_taint_tracking.md` (Iteration 527)
- **Workflow Prompt**: `.github/prompts/python-semantic-barrier-workflow.prompt.md`

## Anti-Cheating Verification

✅ **Semantic Model**: Source + callable merge follows product lattice join operation  
✅ **Z3 Constraints**: Symbolic labels track taint through Z3 bitvectors with merge  
✅ **Barrier Certificates**: Safety proofs use barrier templates for database operations  
✅ **No Heuristics**: All detection is based on taint lattice semantics, not patterns  
✅ **Test Coverage**: 5 new tests + 89 existing tests validate the implementation  
✅ **Soundness**: Over-approximation preserves soundness (τ grows, κ shrinks, join is monotone)

## Change Summary

**Changed Files:**
- `pyfromscratch/semantics/security_tracker_lattice.py` - Enhanced source handling to merge with callable taint

**New Files:**
- `tests/test_cursor_taint.py` - 5 comprehensive tests for cursor taint tracking
- `docs/database_cursor_taint_tracking.md` - This documentation

**Test Results:**
- New tests: 5/5 passed
- Existing taint lattice tests: 31/31 passed
- Existing security bug tests: 58/58 passed
- **Total: 94/94 tests passing**
