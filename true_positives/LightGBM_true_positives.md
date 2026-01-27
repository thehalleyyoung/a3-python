# LightGBM True Positives

**Microsoft LightGBM** is a gradient boosting framework.

**Likelihood of Real Issues: MEDIUM** — Standard ML model serialization concerns

## 1. PICKLE_INJECTION in model loading (example code, not library)

**Severity**: MEDIUM  
**Exploitability**: LOW (example code)

```python
# examples/python-guide/advanced_example.py:96
pkl_bst = pickle.load(fin)
```

**Why this is lower severity:**
- This is in example code, not the library itself
- LightGBM's native model format (`.txt`, `.bin`) doesn't use pickle
- Pickle usage is optional, not required

**However:** Users following examples may adopt pickle serialization, inheriting the vulnerability.

**Effective Likelihood: 30%** — Optional pattern, not enforced

---

## 2. LightGBM native format is safe

**Severity**: N/A (good design)

LightGBM's primary model format uses text-based (`.txt`) or custom binary (`.bin`) formats that don't support arbitrary code execution.

```python
# Safe model saving
bst.save_model('model.txt')
bst = lgb.Booster(model_file='model.txt')
```

**This is the recommended approach** and should be highlighted.

---

## 3. No command injection vulnerabilities

LightGBM's Python package wraps the C++ library without shell execution patterns.

---

## 4. No path traversal vulnerabilities

Model paths are handled safely with proper validation.

---

## 5. Potential denial of service via malformed model files

**Severity**: LOW  
**Exploitability**: LOW

Loading a malformed `.txt` model file could potentially cause:
- Excessive memory allocation
- Long parsing times

**Why this is low severity:**
- Requires attacker to provide a model file
- Doesn't lead to code execution
- Standard input validation concern

**Effective Likelihood: 10%**

---

**Summary:** LightGBM is relatively secure because:
1. Its native model format doesn't use pickle
2. Pickle usage is optional (example code only)
3. No subprocess or eval patterns

The main risk is users following pickle-based examples instead of using native formats.

**Recommendation:** Update examples to use native format by default, add warnings about pickle.

**Effective True Positives: 0-1 (example code only)**
