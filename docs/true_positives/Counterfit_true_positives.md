# Counterfit True Positives

**Azure Counterfit** is an AI security testing framework for adversarial ML attacks.

**Likelihood of Real Issues: HIGH** — Multiple `eval()` calls on CLI input

---

## 1. ⚠️ CODE_INJECTION via `eval()` on user CLI input — **TRUE POSITIVE**

**Severity**: HIGH  
**Exploitability**: HIGH (direct CLI input to eval)

```python
# examples/terminal/commands/set.py:48
def get_sample_index(sample_index: str) -> Union[list, int, range, None]:
    try:
        sample_index = eval(sample_index)  # USER INPUT → EVAL
    except Exception as e:
        CFPrint.failed(f"Error parsing '--sample_index {sample_index}: {e}")

# examples/terminal/commands/set.py:71
def get_clip_values(clip_values: str) -> Union[tuple,NoneType]:
    try:
        clip_values = tuple(eval(clip_values))  # USER INPUT → EVAL

# examples/terminal/commands/set.py:91
def parse_numeric(argname: str, val_str: str) -> Union[int, float, None]:
    try:
        val = eval(val_str)  # USER INPUT → EVAL

# examples/terminal/commands/predict.py:64
sample_index = eval(args.index)  # USER INPUT → EVAL
```

**Why this is a REAL vulnerability:**
- Direct `eval()` on CLI argument strings
- No sanitization before evaluation
- Arbitrary code execution: `--sample_index "__import__('os').system('id')"`
- Even though this is a CLI tool, shared scripts using Counterfit could be exploited

**Attack scenario:**
```bash
# Attack via malicious sample_index argument
counterfit --sample_index "__import__('os').system('rm -rf /')"
```

**Effective Likelihood: 80%** — Direct path from CLI input to eval

---

## 2. PICKLE_INJECTION in model loading — Expected for ML tools

**Severity**: MEDIUM (expected behavior)  
**Exploitability**: LOW (users know they're testing models)

```python
# counterfit/targets/digits_mlp.py:21
self.model = pickle.load(f)
```

**Why this is demoted:**
- ML tools that load Python models use pickle
- Users of security testing tools should understand risks

**Effective Likelihood: 10%** — Expected for domain

---

## 3. allow_pickle=True in numpy loading — Standard for ML data

**Severity**: LOW  
**Exploitability**: VERY LOW

**Effective Likelihood: 5%** — Sample data is trusted

---

**Summary (Revised):** Counterfit has **4 real `eval()` code injection vulnerabilities** in CLI parsing. These are not defensible as "expected behavior" — `ast.literal_eval()` should be used instead for parsing Python literals.

**Effective True Positives: 4 (eval on user input)**
