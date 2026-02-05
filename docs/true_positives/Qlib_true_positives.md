# Qlib True Positives

## 1. ~~CODE_INJECTION~~ in `data/data.py:397` — eval(parse_field(field)) — **MITIGATED**

**Severity**: LOW (after analysis)  
**Exploitability**: LOW (Operators prefix blocks most attacks)

```python
# qlib/data/data.py:397
expression = eval(parse_field(field))
```

**Why this is NOT as severe as initially thought:**
- `parse_field()` transforms ANY function call `func(` to `Operators.func(`
- `Operators` is a restricted wrapper that only allows registered operators
- Injection attempts like `__import__("os")` become `Operators.__import__("os")` → raises `AttributeError`
- Even Python sandbox escapes like `().__class__.__subclasses__()` get transformed and fail

**Remaining risk:** Defense in depth — eval() with unrestricted builtins is still not ideal, but the Operators prefix provides effective mitigation.

**Effective Likelihood: 10%** — Most injection attempts are blocked

---

## 2. CODE_INJECTION in `contrib/model/pytorch_tra.py:140` — eval(self.model_type)

**Severity**: HIGH  
**Exploitability**: MEDIUM (config-controlled)

```python
# qlib/contrib/model/pytorch_tra.py:140
self.model = eval(self.model_type)(**self.model_config).to(device)
```

**Why this is a real vulnerability:**
- `self.model_type` comes from kwargs.get("model_type", "LSTM") in the constructor
- If the model config is loaded from an untrusted YAML/JSON file, an attacker can inject arbitrary code
- Example payload: "__import__('os').system('id')"

**Attack scenario:** If Qlib model configs are shared (GitHub, model zoos, etc.), a malicious config file could execute arbitrary code when loaded.

---

## 3. PICKLE_INJECTION in `contrib/online/utils.py:33` — pickle.load() — **CONTEXT-DEPENDENT**

**Severity**: MEDIUM (context-dependent)  
**Exploitability**: LOW in typical use, MEDIUM in shared environments

```python
# qlib/contrib/online/utils.py:33
with file_path.open("rb") as fr:
    instance = pickle.load(fr)
```

**Analysis:**
- File paths are constructed from `data_path / user_id / filename`
- In typical single-user/single-tenant use, users load their own saved models
- Risk increases in shared environments where:
  - Multiple users access shared storage
  - Models are downloaded from external sources (model zoos, GitHub)
  - `user_id` comes from untrusted input (path traversal possible)

**Effective Likelihood: 30%** — Real risk only in shared/download scenarios

---

## 4. DIV_ZERO in `backtest/position.py:343` — trade_val / trade_price (DSE-validated)

**Severity**: MEDIUM  
**Crashability**: HIGH (zero price edge case)

```python
# qlib/backtest/position.py:343
def _buy_stock(self, stock_id, trade_val, cost, trade_price):
    trade_amount = trade_val / trade_price  # Crash if trade_price == 0
```

**Why this is a real crash bug:**
- In financial markets, stocks can have a price of 0 during:
  - Delisting events
  - Stock splits with temporary 0 price
  - Data corruption or missing data filled with 0
- No guard against trade_price == 0
- DSE confirmed: passing trade_price=0 causes ZeroDivisionError

**Crash scenario:** Backtesting historical data with delisted stocks or corrupted price data will crash the backtest, potentially losing hours of computation.

---

## 5. DIV_ZERO in `backtest/report.py:533` — trade_price / base_price (DSE-validated)

**Severity**: MEDIUM  
**Crashability**: HIGH (price advantage calculation)

```python
# qlib/backtest/report.py:533
def func(trade_dir, trade_price, base_price):
    sign = 1 - trade_dir * 2
    return sign * (trade_price / base_price - 1)  # Crash if base_price == 0
```

**Why this is a real crash bug:**
- base_price is computed from order aggregation and can be 0 if:
  - No orders executed (empty order book)
  - Division by zero in upstream base_volume calculation
- The price advantage calculation is a common metric in backtesting
- DSE confirmed: passing base_price=0 causes ZeroDivisionError

**Crash scenario:** Aggregating order indicators for days with no trading activity crashes the report generation.
---

## 6. Crash Bug Analysis (Iteration 610)

### Summary

After Iteration 610 FP reduction fixes:

| Before Fixes | After Fixes | Reduction |
|-------------|-------------|-----------|
| 16 crash bugs | 12 crash bugs | 25% |

### Fixes Applied

1. **BOUNDS bugs eliminated (4 bugs)** - Dict assignment (`dict[key] = value`) was incorrectly flagged. Fixed by excluding `STORE_SUBSCR` from BOUNDS detection.

2. **Type annotation nullability** - Parameters with non-Optional type hints now assumed NOT_NONE, reducing false NULL_PTR reports.

### Remaining Bugs (12) - All False Positives

| Bug Type | Count | Root Cause |
|----------|-------|------------|
| NULL_PTR | 10 | Local variables not tracked / Chained attr access |
| ITERATOR_INVALID | 2 | Generator StopIteration is expected |

**Key Insight:** All 12 remaining bugs are false positives from:
- Local variables created by `BUILD_MAP`/`BUILD_LIST` (always non-None)
- Chained attribute access on typed parameters
- Generator iteration (expected behavior)

### True Crash Bugs in Qlib

The only confirmed crash bugs remain:
- **DIV_ZERO in position.py:343** (DSE validated)
- **DIV_ZERO in report.py:533** (DSE validated)

These were already documented above and are **true positives**.