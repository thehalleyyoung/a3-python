# Presidio True Positives

**Microsoft Presidio** is a PII (Personally Identifiable Information) detection and anonymization library.

**Likelihood of Real Issues: MEDIUM** — Regex handling with external patterns

## 1. REGEX_INJECTION / ReDoS in `pattern_recognizer.py`

**Severity**: MEDIUM  
**Exploitability**: MEDIUM (custom recognizers)

```python
# presidio-analyzer/presidio_analyzer/pattern_recognizer.py
import regex as re
# ...
pattern = Pattern(name="custom", regex=user_provided_regex, score=1.0)
```

**Why this is a real vulnerability:**
- Presidio allows custom PII recognizers with user-defined regex patterns
- Malicious regex can cause ReDoS (Regular Expression Denial of Service)
- If custom recognizers are loaded from external configs, attackers can cause CPU exhaustion

**Attack scenario:**
1. Organization uses Presidio with custom recognizers from a shared config
2. Attacker modifies config to include ReDoS pattern: `"(a+)+$"`
3. Processing text with "aaaaaaaaaaaaaaX" hangs indefinitely

**Effective Likelihood: 50%** — Custom recognizers are common but usually trusted

---

## 2. Bypass of PII detection (adversarial evasion)

**Severity**: MEDIUM  
**Exploitability**: HIGH (but this is expected)

PII detection can be evaded with:
- Unicode lookalikes (е vs e)
- Whitespace insertion (123-45-6789 → 123 45 6789)
- Homoglyph attacks

**Why this is not a "bug":**
- This is inherent to regex-based PII detection
- Presidio documents these limitations
- It's a security consideration for users, not a vulnerability in Presidio

**Effective Likelihood: N/A** — Expected behavior, not a bug

---

## 3. No pickle vulnerabilities

Presidio doesn't use pickle for recognizer serialization. Recognizers are defined in code or loaded from structured configs (YAML/JSON).

**Effective Likelihood: 0%**

---

## 4. No command injection vulnerabilities

Presidio is a pure analysis library without subprocess execution.

**Effective Likelihood: 0%**

---

## 5. Potential information leakage in error messages

**Severity**: LOW  
**Exploitability**: LOW

Detailed error messages might reveal:
- Internal regex patterns
- File paths
- Configuration details

**Why this is low severity:**
- Standard logging concern
- No direct security impact

**Effective Likelihood: 10%**

---

**Summary:** Presidio's main security concern is ReDoS when using custom recognizers from untrusted sources. The library itself is well-designed with no major vulnerabilities.

**Recommendations:**
1. Validate regex complexity when loading custom recognizers
2. Use the `regex` library's timeout features
3. Document ReDoS risks in custom recognizer documentation

**Effective True Positives: 1 (ReDoS with custom patterns)**
