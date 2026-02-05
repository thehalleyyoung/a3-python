# Guidance True Positives

**Microsoft Guidance** is an LLM control/constrained decoding library. It's designed to guide LLM outputs.

**Likelihood of Real Issues: LOW**

Guidance is a low-level LLM control library with minimal attack surface. Most operations are local prompt manipulation.

## 1. No high-severity security vulnerabilities found

Guidance primarily:
- Constructs prompts programmatically
- Applies grammar constraints to LLM outputs
- Runs locally against LLM APIs

**Why Guidance is relatively safe:**
- No `eval()` or `exec()` patterns found
- No pickle deserialization of external data
- No subprocess execution
- No file path handling of untrusted inputs

## 2. Potential prompt injection in templating

**Severity**: LOW  
**Exploitability**: N/A (design intent)

Guidance templates interpolate user values into prompts. This is the intended behavior, not a vulnerability.

```python
# This is expected usage, not a bug
guidance_template = "{{user_input}}"
```

## 3. LLM response handling

**Severity**: LOW  
**Exploitability**: LOW

LLM responses are parsed and may be used in subsequent operations. If responses contain unexpected content, downstream code could behave unexpectedly.

**Attack scenario:** None identified - responses are handled as data, not executed.

## 4. API key exposure in logs

**Severity**: LOW (standard concern)

Like most LLM libraries, API keys must be configured. Improper logging could expose them.

**Mitigation:** Standard secrets management practices.

## 5. No crash bugs with real-world impact identified

Guidance is a well-structured library with proper error handling.

---

**Summary:** Guidance has no significant security vulnerabilities. It's a local tool for LLM interaction with no dangerous patterns. The main concern is standard LLM security (prompt injection, API key management), which is inherent to all LLM tools.

**Effective True Positives: 0**
