# Shell Check Implementation: Barrier-Theoretic Grounding

## Context-Dependent Safety for COMMAND_INJECTION

### The Problem

The subprocess module has **context-dependent safety**:
- `subprocess.run(tainted_cmd, shell=True)` → UNSAFE (shell interprets metacharacters)
- `subprocess.run(tainted_list, shell=False)` → SAFE (no shell interpretation, array passed directly to execve)

This is a **conditional barrier**: safety depends on a runtime configuration parameter.

### Barrier-Theoretic Model

Define the unsafe region for COMMAND_INJECTION at sink `subprocess.run`:

$$U_{cmd\_inj}(σ) = \begin{cases}
\{σ \mid \pi = \pi_{subprocess.run} \land \tau(arg_0) = 1 \land shell(σ) = 1\} & \text{if } shell \text{ is observable} \\
\{σ \mid \pi = \pi_{subprocess.run} \land \tau(arg_0) = 1\} & \text{if } shell \text{ is unknown}
\end{cases}$$

Where:
- $\tau(arg_0) = 1$ means the command argument is tainted
- $shell(σ) \in \{0, 1\}$ is the value of the shell parameter
- Conservative: if shell is unknown/symbolic, assume it could be 1

### Implementation in `check_sink_taint`

```python
if contract.shell_check:
    shell_value = kwargs.get('shell', False)  # Default is False per Python docs
    
    # Extract concrete value from SymbolicValue
    if is_symbolic(shell_value):
        shell_value = extract_concrete_bool(shell_value)
    
    # Skip violation if shell is concretely False
    if not shell_value:
        continue  # Safe for this contract
```

This implements the barrier condition:
- **If shell is concretely False**: σ ∉ U (not in unsafe region)
- **If shell is concretely True**: Check if τ(arg_0) = 1 to decide σ ∈ U
- **If shell is symbolic**: Conservative - assume σ could be in U

### Soundness Proof Sketch

**Theorem**: The shell_check implementation is sound (never misses bugs).

**Proof**:
1. If `shell=False` (concrete), then actual Python behavior is safe (no shell parsing)
   - Therefore σ ∉ Unsafe in actual semantics `Sem_subprocess.run`
   - We report SAFE ✓
   
2. If `shell=True` (concrete) and arg is tainted, then actual Python behavior is unsafe
   - Therefore σ ∈ Unsafe in actual semantics
   - We report BUG ✓
   
3. If shell is symbolic, we conservatively assume shell could be True
   - Over-approximation: $R_{subprocess.run} ⊇ Sem_{subprocess.run}$
   - We report BUG (or UNKNOWN depending on taint) ✓
   - This may cause false positives but never false negatives

QED.

### Precision Improvement (Iteration 558)

**Before (Iteration 557)**: Extraction failed to recognize `IntVal(0)` as False
- Result: All cases treated as "shell is unknown" → conservative → false positives

**After (Iteration 558)**: Correctly extract `IntVal(0)` → `False`
- Result: Concrete shell=False cases correctly identified → precision improved
- Soundness maintained: Unknown cases still conservative

### Relation to Other Context-Dependent Checks

Similar patterns:
1. **parameterized_check** (SQL): Safe if params argument provided
   ```python
   cursor.execute(query, params)  # Safe - parameterized
   cursor.execute(query)          # Unsafe - string concatenation
   ```

2. **loader_check** (YAML): Safe if SafeLoader specified
   ```python
   yaml.load(data, Loader=yaml.SafeLoader)  # Safe
   yaml.load(data)                           # Unsafe - arbitrary Python execution
   ```

3. **entity_check** (XML): Safe if entity resolution disabled
   ```python
   parse(xml, forbid_dtd=True)      # Safe
   parse(xml)                        # Unsafe - XXE possible
   ```

All follow the same barrier-theoretic pattern:
- Unsafe region depends on configuration parameter
- Extract concrete value if available
- Conservative if parameter is symbolic/unknown
- Sound over-approximation: $R_f ⊇ Sem_f$
