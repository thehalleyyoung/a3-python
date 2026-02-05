# MSTICPY True Positives

MSTICPY is a Microsoft security investigation library. Many findings require careful analysis:
- SSRF: Most HTTP requests are to well-known registries (RDAP, threat intel providers)
- PATH_INJECTION: Users control their own config paths in Jupyter notebooks

## 1. DIV_ZERO in `data/drivers/cybereason_driver.py:461` — Pagination calculation (DSE-validated ✓)

**Severity**: MEDIUM  
**Crashability**: HIGH (API response dependent)

```python
# msticpy/data/drivers/cybereason_driver.py:461
def _create_paginated_query_tasks(
    self, body, page_size, pagination_token, total_results, timeout, max_retry
):
    total_pages: int = total_results // page_size + 1  # Crash if page_size == 0
```

**Why this is a real crash bug:**
- `page_size` is a function parameter that could be 0
- If the Cybereason API returns unexpected pagination info, or if default values are misconfigured, this crashes
- DSE confirmed: passing `page_size=0` causes `ZeroDivisionError`

**Crash scenario:** 
1. API response indicates 0 results per page
2. Driver calculates pagination and crashes
3. Security analyst loses their query results

**Mitigation:** Add `if page_size <= 0: page_size = DEFAULT_PAGE_SIZE` guard.

---

## 2. XXE/XML_BOMB in `data/sql_to_kql.py:200` — XML parsing

**Severity**: LOW (False Positive)  
**Exploitability**: N/A

```python
# msticpy/data/sql_to_kql.py:200
parsed_sql = parse(sql)  # This is SQL parsing, NOT XML parsing
```

**Why this is a FALSE POSITIVE:**
- The `parse()` function is from `mo_sql_parsing`, a SQL parser
- It does NOT parse XML
- Our detector incorrectly flagged this due to the generic function name

**Conclusion:** Not a real vulnerability. The SQL to KQL converter is safe.

---

## 3. SSRF in `context/ip_utils.py:647` — RDAP lookup

**Severity**: LOW  
**Exploitability**: LOW (hardcoded registries)

```python
# msticpy/context/ip_utils.py:647
def _run_rdap_query(url: str) -> httpx.Response | None:
    return httpx.get(url)
```

**Why this is low severity:**
- URLs are constructed from hardcoded RDAP registry endpoints (ARIN, RIPE, APNIC, etc.)
- User input is an IP address, not a URL
- The IP is appended to registry URLs: `f"{registry_url}{ip_address}"`
- No way to redirect to arbitrary URLs

**Note:** If the IP validation is bypassed, there could be some risk, but the attack surface is minimal.

---

## 4. PATH_INJECTION in `init/mp_plugins.py:87` — Plugin loading from path

**Severity**: MEDIUM  
**Exploitability**: LOW (config-controlled)

```python
# msticpy/init/mp_plugins.py:87
def load_plugins_from_path(plugin_path: str | Path):
    sys.path.append(str(plugin_path))
    for module_file in Path(plugin_path).glob("*.py"):
        module = import_module(module_file.stem)
```

**Why this is a real vulnerability:**
- Plugin paths come from `msticpyconfig.yaml`
- If the config file is writable by an attacker, they can add malicious plugin paths
- Any `.py` file in the specified path gets imported and executed

**Attack scenario:**
1. Attacker gains write access to `msticpyconfig.yaml` (shared notebook environment)
2. Adds a plugin path pointing to their malicious code
3. Next time MSTICPY loads, arbitrary code executes

**Mitigation:** Validate plugin paths, consider code signing for plugins.

---

## 5. SSRF in `context/domain_utils.py:119` — Browshot screenshot API

**Severity**: LOW  
**Exploitability**: LOW (intentional feature)

```python
# msticpy/context/domain_utils.py:119
id_string = f"https://api.browshot.com/api/v1/screenshot/create?url={url}/..."
id_data = httpx.get(id_string, ...)
```

**Why this is intentional behavior:**
- The `screenshot()` function takes a URL and screenshots it via Browshot API
- This IS the intended functionality — users provide URLs to screenshot
- The "SSRF" is the feature, not a bug
- Browshot handles the actual URL fetching, not MSTICPY

**Note:** Listed for awareness, but this is expected behavior for a screenshot function.

---

**Summary:** MSTICPY's main real issues are:
1. **DIV_ZERO in pagination** — real crash bug that should be fixed
2. **Plugin loading** — could be exploited in shared environments
3. Most SSRF findings are false positives (hardcoded URLs or intentional features)
