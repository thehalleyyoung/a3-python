# Iteration 43: Expanded Standard Library Contracts

## Goal
Reduce UNKNOWN results by adding contracts for commonly-used Python builtins that were previously causing havoc (over-approximated as "may do anything").

## Changes

### Added 26 New Contracts

Added contracts for commonly-used builtins and stdlib functions:

**Collection constructors:**
- `list()` - iterates argument, allocates new list
- `tuple()` - iterates argument, allocates immutable tuple
- `set()` - iterates argument, checks hashability
- `dict()` - builds dictionary from arguments
- `frozenset()` - immutable set constructor

**Type conversions:**
- `float()` - numeric conversion
- `bool()` - truthiness check (calls `__bool__` or `__len__`)
- `chr()` - int to Unicode character
- `ord()` - character to int (0-0x10FFFF range)
- `hex()`, `oct()`, `bin()` - integer string representations

**Logical operations:**
- `any()` - returns True if any element is truthy
- `all()` - returns True if all elements are truthy

**Iteration/ordering:**
- `sorted()` - creates new sorted list
- `enumerate()` - creates enumerate iterator
- `zip()` - creates zip iterator
- `reversed()` - creates reverse iterator

**Numeric operations:**
- `round()` - rounding to integer or n digits
- `pow()` - exponentiation (may raise ValueError, ZeroDivisionError)
- `divmod()` - returns (quotient, remainder) tuple

**Introspection/reflection:**
- `hash()` - calls `__hash__`, may read heap
- `id()` - pure identity function (memory address)
- `type()` - pure type query
- `hasattr()` - suppresses exceptions from getattr
- `callable()` - checks for `__call__` method
- `repr()` - calls `__repr__`, may read heap

## Contract Design Principles

All contracts follow these rules:
1. **Over-approximation**: `Sem_f ⊆ R_f` (soundness)
2. **Justified**: Based on Python docs, language spec, or CPython source
3. **Explicit footprint**: Clearly state `may_read`, `may_write`, `may_allocate`
4. **Exception modeling**: List specific exceptions that may be raised

## Soundness Considerations

- Functions calling dunder methods (`__bool__`, `__hash__`, `__repr__`, `__str__`) conservatively assume:
  - `may_read={'*'}` (dunder methods may read arbitrary heap locations)
  - `may_raise={'*'}` (dunder methods may raise anything) where applicable
- Constructors that iterate arguments use `may_read={'*'}` (iteration may access heap)
- Pure mathematical functions use `HeapEffect.pure()` when justified

## Impact on Analysis

These contracts reduce UNKNOWN results in two ways:

1. **Reduced havoc**: Known-pure functions no longer trigger conservative "may mutate anything" assumptions
2. **Better reachability**: Exception specifications enable more precise exceptional control flow

### Example: Before vs After

**Before** (no contract for `sorted()`):
```python
def process(items):
    sorted_items = sorted(items)  # UNKNOWN: havoc call
    return sorted_items[0]  # Analyzer must assume anything is possible
```

**After** (with `sorted()` contract):
```python
def process(items):
    sorted_items = sorted(items)  # Known: pure read, allocates list, may raise TypeError
    return sorted_items[0]  # BOUNDS check is precise: list indexing
```

## Testing

All 538 tests pass with the new contracts. No regressions observed.

## Next Steps

Future contract additions should focus on:
1. **I/O operations** (`open`, `read`, `write`) - carefully model side effects
2. **Mutable container methods** (`list.append`, `dict.update`) - precise mutation footprints
3. **String methods** (`str.format`, `str.split`) - mostly pure operations
4. **Math module** (`math.sin`, `math.cos`, etc.) - pure mathematical functions
5. **os/sys modules** - external state interactions (require careful modeling)

## References

- Python Language Reference: https://docs.python.org/3/reference/
- Python Library Reference: https://docs.python.org/3/library/
- Contract schema: `pyfromscratch/contracts/schema.py`
- Contract format: `pyfromscratch/contracts/FORMAT.md`
