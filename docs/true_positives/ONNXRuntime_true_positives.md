# ONNX Runtime True Positives

**Microsoft ONNX Runtime** is a high-performance ML inference engine.

**Likelihood of Real Issues: LOW** — Mature, security-conscious project

## 1. Model loading security (by design)

**Severity**: N/A (good design)

ONNX Runtime loads `.onnx` files which are protobuf-based, not pickle-based. This is inherently safer than PyTorch's pickle-based checkpoints.

```python
# Safe model loading
session = ort.InferenceSession("model.onnx")
```

**Why ONNX is safer:**
- Protobuf format doesn't support arbitrary code execution
- Model structure is well-defined and validated
- Custom ops require explicit registration (can't be injected via model)

---

## 2. Custom operator loading (potential concern)

**Severity**: MEDIUM  
**Exploitability**: LOW (requires explicit action)

Custom operators are loaded as shared libraries (`.so`/`.dll`). Loading untrusted custom ops could execute malicious code.

```python
# This loads native code
sess_options.register_custom_ops_library("custom_op.so")
```

**Why this is low exploitability:**
- Users must explicitly load custom op libraries
- Libraries are native code, not hidden in model files
- Clear distinction between model and code

**Effective Likelihood: 5%** — Explicit action required

---

## 3. Python package has minimal attack surface

The Python bindings (`onnxruntime/python/`) are thin wrappers around the C++ runtime. Most security-critical code is in C++, not Python.

**Security benefits:**
- Less Python-specific vulnerabilities (no pickle, eval, etc.)
- Memory safety handled by well-tested C++ code
- Python just handles marshalling/unmarshalling

---

## 4. No command injection vulnerabilities

ONNX Runtime doesn't execute shell commands.

---

## 5. Denial of service via malformed models

**Severity**: LOW  
**Exploitability**: LOW

Malformed ONNX models could potentially cause:
- Excessive memory allocation
- Long computation times
- Crashes in native code

**Why this is low severity:**
- ONNX models are validated before execution
- Standard fuzzing has been applied to the parser
- Doesn't lead to code execution

**Effective Likelihood: 5%**

---

**Summary:** ONNX Runtime is a well-designed, mature project with minimal Python-side vulnerabilities:

1. Uses protobuf (not pickle) for model format
2. Custom ops require explicit loading
3. Python package is a thin wrapper
4. No eval/exec patterns

**Effective True Positives: 0-1 (custom op loading is the only concern)**

**ONNX Runtime is an example of security-conscious ML infrastructure design.**
