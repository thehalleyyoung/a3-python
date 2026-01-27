# RD-Agent True Positives

**Microsoft RD-Agent** is an AI-driven research automation tool. It automates R&D processes using LLMs.

**Likelihood of Real Issues: HIGH** — Tarfile path traversal + eval + unvalidated subprocess

---

## 1. ⚠️ TARFILE PATH TRAVERSAL — **TRUE POSITIVE**

**Severity**: HIGH  
**Exploitability**: HIGH (data comes from Kaggle downloads)

```python
# rdagent/scenarios/data_science/proposal/exp_gen/select/submit.py:630-631
def extract_tar(tar_path: str, to_dir: str = "log") -> str:
    with tarfile.open(tar_path, mode="r:*") as tar:
        tar.extractall(path=to_dir)  # NO PATH VALIDATION!

# rdagent/scenarios/kaggle/kaggle_crawler.py:153
with tarfile.open(tar_path, "r:gz") if is_gzip_file else tarfile.open(tar_path, "r") as tar_ref:
    # Uses shell commands but still extracts from untrusted sources
```

**Why this is a REAL vulnerability:**
- Downloads tar files from Kaggle competitions
- No validation that archive members don't escape with `../` paths
- A malicious tar archive could write files anywhere: `../../.bashrc`, `../../.ssh/authorized_keys`
- Python 3.12+ has `filter='data'` parameter, but this code doesn't use it

**Attack scenario:**
1. Attacker creates Kaggle competition with malicious tar archive
2. RD-Agent user downloads and extracts it
3. Malicious files written outside target directory

**Effective Likelihood: 70%** — Kaggle data is semi-trusted but not verified

---

## 2. ⚠️ CODE_INJECTION via `eval()` in Kaggle templates — **TRUE POSITIVE**

**Severity**: MEDIUM-HIGH  
**Exploitability**: MEDIUM (eval on generated code)

```python
# rdagent/scenarios/kaggle/experiment/utils.py:64
'select_m = eval(mc.__name__.replace("model", "select"))',
```

**Why this is concerning:**
- Uses `eval()` to dynamically resolve module names
- If `mc.__name__` is controlled by external input (model definitions), code execution possible
- Template code that gets eval'd during experiment runs

**Effective Likelihood: 40%** — Depends on how model classes are named

---

## 3. ZIPFILE PATH TRAVERSAL — **TRUE POSITIVE**

**Severity**: HIGH  
**Exploitability**: HIGH

```python
# rdagent/utils/env.py:189
z.extractall(folder_path)  # No member filtering

# rdagent/scenarios/kaggle/kaggle_crawler.py:205
zip_ref.extractall(unzip_target_path)  # No member filtering
```

Same issue as tarfile — no validation of archive member paths.

**Effective Likelihood: 70%**

---

## 4. PICKLE in session/knowledge loading — Lower priority

**Severity**: MEDIUM  
**Exploitability**: LOW (local persistence)

```python
# rdagent/log/utils/folder.py:24
session_obj: LoopBase = pickle.load(f)

# rdagent/log/storage.py:95
content = pickle.load(f)
```

**Why this is demoted:**
- Session files are user-local
- Knowledge bases are algorithm-specific
- Sharing pickle files is uncommon

**Effective Likelihood: 15%** — Only in shared environments

---

## 5. SUBPROCESS with untrusted paths — **MEDIUM CONCERN**

**Severity**: MEDIUM  
**Exploitability**: MEDIUM

```python
# rdagent/scenarios/kaggle/kaggle_crawler.py:140-163
# Shell commands with paths from Kaggle downloads
mleb_env.check_output(
    f"unzip -o ./{zip_path.relative_to(competition_local_path)} -d ..."
)
```

**Why this is concerning:**
- Paths come from downloaded archive names
- If archive names contain shell metacharacters, command injection possible
- Should use `shlex.quote()` or subprocess list form

**Effective Likelihood: 30%**

---

**Summary (Revised):** RD-Agent has **3-4 real vulnerabilities**:
1. **Tarfile path traversal** — extracting Kaggle downloads without validation
2. **Zipfile path traversal** — same issue  
3. **Shell command injection risk** — paths not quoted
4. **eval() on dynamic names** — code injection possible

The pickle issues are lower priority (local persistence).

**Effective True Positives: 4**
