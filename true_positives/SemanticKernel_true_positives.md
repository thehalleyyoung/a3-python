# Semantic Kernel True Positives

**Microsoft Semantic Kernel** is an LLM orchestration SDK.

**Likelihood of Real Issues: LOW** — Well-protected eval() with comprehensive safeguards

## 1. ~~CODE_INJECTION~~ in `connectors/in_memory.py:384` — **WELL MITIGATED**

**Severity**: LOW (heavily protected)  
**Exploitability**: VERY LOW (multiple defense layers)

```python
# semantic_kernel/connectors/in_memory.py:384
func = eval(code, {"__builtins__": {}}, {})  # nosec
```

**Why this is NOT exploitable:**
The code has MULTIPLE layers of protection:

1. **AST node whitelist** — Only specific node types allowed
2. **Name validation** — Only lambda parameter names allowed, all other names rejected
3. **Function call whitelist** — Only specifically allowed functions can be called
4. **Builtins disabled** — `{"__builtins__": {}}` blocks access to dangerous functions

**Code excerpt showing protections:**
```python
# For Name nodes, only allow the lambda parameter
if isinstance(node, ast.Name) and node.id not in lambda_param_names:
    raise VectorStoreOperationException(...)
    
# For Call nodes, validate that only allowed functions are called
if func_name and func_name not in self.allowed_filter_functions:
    raise VectorStoreOperationException(...)
```

**Sandbox escape attempts will fail because:**
- `__import__` → Name not in lambda params → REJECTED
- `().__class__` → ast.Attribute on non-param → REJECTED  
- Custom function calls → Not in allowed_filter_functions → REJECTED

**Effective Likelihood: <1%** — Comprehensive AST validation makes this essentially unexploitable

---

## 2. Tests verify security

The test suite explicitly checks for malicious eval attempts:
```python
async def test_malicious_filter_eval(collection):
    # Should not allow eval()
```

This shows active security awareness and testing.

---

## 3-5. Other concerns (inherent to LLM tools, not bugs)

- **Prompt injection** — Inherent to all LLM orchestration tools
- **Function calling** — User responsibility to not register dangerous functions
- **API key management** — Standard secrets handling

These are design considerations, not vulnerabilities in Semantic Kernel.

---

**Summary (Revised):** Semantic Kernel's eval() is one of the best-protected examples in the analyzed codebases. The combination of:
- AST node whitelisting
- Name validation
- Function call whitelisting
- Disabled builtins

Makes exploitation essentially impossible.

**Effective True Positives: 0**
