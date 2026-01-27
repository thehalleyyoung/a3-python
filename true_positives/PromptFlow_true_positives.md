# PromptFlow True Positives

PromptFlow is Microsoft's LLM orchestration framework.

**Likelihood of Real Issues: LOW** — Most concerns are inherent to LLM tools, not PromptFlow-specific bugs

## 1. PROMPT_INJECTION risk — **Inherent to LLM tools, not a bug**

**Severity**: N/A (design constraint)  
**Exploitability**: N/A

PromptFlow executes flows that construct prompts from user inputs. This is the intended purpose.

**Why this is NOT a bug:**
- All LLM orchestration tools face this by design
- PromptFlow provides guardrails but can't eliminate the fundamental LLM limitation
- This is like saying "web browsers allow displaying untrusted content"
- User responsibility to validate outputs

**Effective Likelihood: N/A** — Not a bug, inherent to the domain

---

## 2. CODE_INJECTION via Python tool nodes — **Expected behavior**

**Severity**: N/A (expected)  
**Exploitability**: N/A

PromptFlow supports Python tool nodes that execute code defined in the flow.

**Why this is NOT a bug:**
- Flows ARE code - users running a flow are running code they (should) have reviewed
- Same trust model as `npm install` or `pip install`
- Running untrusted flows = running untrusted code = user error

**Effective Likelihood: N/A** — Expected behavior

---

## 3. SSRF via connection configurations — **User-controlled config, not a bug**

Connections point to URLs configured by the user. Users pointing at internal services is their choice.

**Effective Likelihood: <5%** — Config is user-controlled

---

## 4-5. PATH_INJECTION and PICKLE_INJECTION — **Not found in core library**

- Pickle usage is only in example flows, not the core library
- Path handling is standard Python pathlib usage

---

**Summary (Revised):** PromptFlow has NO significant security vulnerabilities in its core library. The concerns listed in the original report are:
1. **Inherent to LLM tools** (prompt injection)
2. **Expected behavior** (code execution in flows)
3. **User configuration choices** (connection URLs)

**Effective True Positives: 0**
