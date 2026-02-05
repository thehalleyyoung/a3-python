# Type-Based Sanitizers for Improved Precision

## Overview

This document describes the **type-based sanitizer** enhancement to the PythonFromScratch security analysis. Type conversions like `int()`, `bool()`, `datetime.fromisoformat()`, `pathlib.Path.resolve()`, and `ipaddress.ip_address()` now act as sanitizers by constraining the value domain.

## Barrier-Theoretic Justification

For a type conversion function `T: V → T(V)`, if `T` validates/constrains the domain:

```
Safe_k(T(v)) ⟺ domain(T) ∩ exploit_strings(k) = ∅
```

Where:
- `domain(T)` is the set of possible outputs from `T`
- `exploit_strings(k)` is the set of strings that can exploit sink `k`
- If these sets are disjoint, then `T(v)` is provably safe for sink `k`

### Examples

1. **int() for SQL Injection**
   - `domain(int) = {..., -1, 0, 1, 2, ...}` (integers)
   - `exploit_strings(SQL_EXECUTE) = {"' OR 1=1--", "DROP TABLE", ...}` (SQL operators)
   - `domain(int) ∩ exploit_strings(SQL_EXECUTE) = ∅` ✓

2. **bool() for Command Injection**
   - `domain(bool) = {True, False}`
   - `exploit_strings(COMMAND_SHELL) = {"; rm -rf /", "$(malicious)", ...}` (shell metacharacters)
   - `domain(bool) ∩ exploit_strings(COMMAND_SHELL) = ∅` ✓

3. **ipaddress.ip_address() for SSRF**
   - `domain(ip_address) = {valid IPv4/IPv6 addresses}`
   - `exploit_strings(HTTP_REQUEST) = {"http://internal.local", "file:///etc/passwd", ...}`
   - IP validation prevents domain hijacking and localhost bypass ✓

## Implementation

### New Sanitizer Contracts

Added 16+ new type-based sanitizer contracts in `pyfromscratch/contracts/security_lattice.py`:

#### Numeric Conversions
- `builtins.int` → sanitizes SQL, FILE_PATH, COMMAND_SHELL
- `int` → sanitizes SQL, FILE_PATH, COMMAND_SHELL
- `builtins.float` → sanitizes SQL_EXECUTE
- `builtins.bool` → sanitizes SQL, COMMAND_SHELL, FILE_PATH
- `bool` → sanitizes SQL, COMMAND_SHELL, FILE_PATH

#### String Validation Methods
- `str.isdigit` → sanitizes SQL, FILE_PATH (all digits)
- `str.isalpha` → sanitizes SQL, FILE_PATH, COMMAND_SHELL (all alphabetic)
- `str.isalnum` → sanitizes SQL, FILE_PATH, COMMAND_SHELL (alphanumeric only)

#### Datetime Parsing
- `datetime.datetime.fromisoformat` → sanitizes SQL_EXECUTE
- `datetime.date.fromisoformat` → sanitizes SQL_EXECUTE
- `datetime.datetime.strptime` → sanitizes SQL_EXECUTE

#### Path Canonicalization
- `pathlib.Path` → sanitizes FILE_PATH (canonicalization)
- `pathlib.Path.resolve` → sanitizes FILE_PATH (absolute path resolution)

#### IP Address Validation
- `ipaddress.ip_address` → sanitizes SQL, HTTP_REQUEST, NETWORK_BIND
- `ipaddress.IPv4Address` → sanitizes SQL, HTTP_REQUEST, NETWORK_BIND
- `ipaddress.IPv6Address` → sanitizes SQL, HTTP_REQUEST, NETWORK_BIND

#### Enum Constraint
- `enum.Enum` → sanitizes SQL, COMMAND_SHELL, FILE_PATH (allowlist)

#### Safe Deserialization
- `json.loads` → sanitizes DESERIALIZE (no code execution)
- `json.load` → sanitizes DESERIALIZE

#### Bytes/Encoding
- `builtins.bytes` → sanitizes SQL_EXECUTE
- `str.encode` → sanitizes SQL_EXECUTE
- `bytes.decode` → sanitizes SQL_EXECUTE

## Bug Fix

Fixed a critical bug in `apply_sanitizer()` where it was calling `result.sanitize(contract.sanitizer_type)` which uses the **global** `SANITIZER_TO_SINKS` mapping instead of the **contract-specific** `applicable_sinks`. This caused over-sanitization (e.g., `float()` incorrectly sanitizing COMMAND_SHELL).

**Before:**
```python
for sink in sinks:
    result = result.sanitize(contract.sanitizer_type)  # Wrong! Uses global mapping
```

**After:**
```python
new_kappa = input_label.kappa
for sink in sinks:
    new_kappa |= (1 << sink)  # Direct bit manipulation with contract-specific sinks
```

## Test Coverage

Created `tests/test_type_based_sanitizers.py` with 16 tests:

### Positive Tests (10)
- `test_int_sanitizes_sql` - int() prevents SQL injection
- `test_float_sanitizes_sql` - float() prevents SQL injection
- `test_bool_sanitizes_multiple_sinks` - bool() prevents SQL, command, path injection
- `test_datetime_sanitizes_sql` - datetime parsing validates format
- `test_pathlib_canonicalize` - Path.resolve() prevents traversal
- `test_ip_address_validation` - IP validation prevents SSRF
- `test_enum_constrains_to_allowlist` - Enum constrains to predefined values
- `test_json_loads_safe_deserialization` - JSON is safe (no code exec)
- `test_str_isdigit_validation` - isdigit() validates numeric format
- `test_str_isalnum_validation` - isalnum() validates alphanumeric

### Composition Tests (3)
- `test_int_then_string_interpolation` - int() preserves safety after str()
- `test_uuid_validation_for_sql_and_path` - UUID sanitizes multiple sinks
- `test_bytes_encoding_sanitizes_sql` - bytes() constrains domain

### Negative Tests (3)
- `test_int_does_not_sanitize_code_eval` - int() doesn't sanitize CODE_EVAL
- `test_float_does_not_sanitize_command` - float() doesn't sanitize COMMAND_SHELL
- `test_datetime_does_not_sanitize_html` - datetime doesn't sanitize HTML

All 16 tests pass. Existing 89 tests in `test_taint_lattice.py` and `test_security_bugs.py` still pass.

## Demo

`scripts/demo_type_based_sanitizers.py` demonstrates:
1. int() sanitization for SQL injection
2. bool() sanitization for multiple sinks
3. datetime validation
4. Path canonicalization
5. IP address validation
6. Enum allowlist constraint
7. JSON safe deserialization
8. Comparison with string escaping

## Impact

### Precision Improvement

Type-based sanitizers reduce false positives by recognizing domain constraints:

**Before:**
```python
user_id = int(request.GET['id'])
query = f"SELECT * FROM users WHERE id = {user_id}"
# FALSE POSITIVE: Flagged as SQL injection (tainted)
```

**After:**
```python
user_id = int(request.GET['id'])  # int() sanitizes for SQL
query = f"SELECT * FROM users WHERE id = {user_id}"
# TRUE NEGATIVE: Recognized as safe (integer domain has no SQL operators)
```

### Contract Count

Total sanitizer contracts: **52** (previously ~40, added 12+ type-based)

### Barrier Certificates

Type-based sanitizers enable barrier certificate proofs:

```
B_type(s) = {
    M                           if π ≠ π_sink
    (1 - δ_type_safe(s)) - 1/2  if π = π_sink
}

where δ_type_safe(s) = 1 iff:
    value = T(tainted_input) ∧ domain(T) ∩ exploit_strings(sink) = ∅
```

## Integration with Symbolic VM

Type-based sanitizers integrate with the symbolic VM through:
1. **Source contracts** - mark sources (HTTP, user input, etc.)
2. **Sanitizer contracts** - applied at CALL instructions
3. **Sink contracts** - check safety at sinks (SQL execute, shell, etc.)

When the VM encounters `cursor.execute(int(user_input))`:
1. `user_input` is tainted from source
2. `int()` call applies TYPE_CONVERSION sanitizer
3. `cursor.execute()` sink check passes (kappa has SQL_EXECUTE bit set)

## Future Work

1. **Context-sensitive type tracking** - track which type a value has after conversion
2. **Numeric range constraints** - `int(x, base=10)` with range checks
3. **Regex validation** - `re.match(r'^[a-zA-Z0-9]+$', x)` as sanitizer
4. **Custom validators** - user-defined validation functions
5. **ORM type validation** - Django/SQLAlchemy field types as sanitizers

## References

- Barrier certificate theory: `barrier-certificate-theory.tex`
- Python adaptation: `python-barrier-certificate-theory.md`
- Taint lattice: `leak_theory.md`
- Implementation: `pyfromscratch/z3model/taint_lattice.py`
- Contracts: `pyfromscratch/contracts/security_lattice.py`
