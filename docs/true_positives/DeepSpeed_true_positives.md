# DeepSpeed True Positives

**Microsoft DeepSpeed** is a deep learning optimization library for distributed training and inference.

**Likelihood of Real Issues: MEDIUM** — Model checkpoint pickle is a real but well-known issue

## 1. PICKLE in `inference/v2/engine_factory.py:63` — Model config loading

**Severity**: MEDIUM  
**Exploitability**: MEDIUM (requires downloading untrusted checkpoints)

```python
# deepspeed/inference/v2/engine_factory.py:63
model_config = pickle.load(open(os.path.join(path, "ds_model_config.pkl"), "rb"))
```

**Context:**
- This loads DeepSpeed-specific model configuration
- The file `ds_model_config.pkl` is created by DeepSpeed's checkpoint saving process
- Users typically save/load their OWN checkpoints

**When this is exploitable:**
- Downloading pre-converted checkpoints from untrusted sources
- Using third-party model repositories that provide DeepSpeed-format checkpoints

**When this is NOT exploitable:**
- Training your own model and loading your own checkpoints
- Converting HuggingFace models yourself (you control the conversion)

**Effective Likelihood: 35%** — Real but limited to untrusted checkpoint downloads

---

## 2. Triton kernel cache — Less concerning

**Severity**: LOW  
**Exploitability**: LOW (requires local write access)

The Triton matmul extension caches kernels as pickle. This requires attacker write access to the local cache directory, which typically means they already have code execution.

**Effective Likelihood: 5%** — Pre-requisite (write access) implies compromise

---

## 3. PyTorch inheritance (not DeepSpeed-specific)

DeepSpeed uses `torch.load()` for general checkpoint loading, which inherits PyTorch's pickle vulnerabilities. This is an industry-wide issue, not specific to DeepSpeed.

---

## 4-5. No additional high-severity findings

- Build scripts use subprocess but only with controlled inputs
- No path traversal vulnerabilities
- No eval/exec patterns

---

**Summary (Revised):** DeepSpeed's main risk is the same as all PyTorch-based tools: loading untrusted checkpoints. The DeepSpeed-specific `ds_model_config.pkl` is an additional pickle file, but the attack scenario (downloading malicious checkpoints) is the same.

**Recommendation:** Document the risk of loading untrusted checkpoints prominently.

**Effective True Positives: 1 (checkpoint loading from untrusted sources)**
