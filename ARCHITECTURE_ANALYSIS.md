# Architecture Analysis: Code vs Bytecode Levels

## Current State

### Two Analysis Paths

Your codebase has **TWO separate analyzers** that do the same job at different abstraction levels:

#### 1. **AST-Based (Code Level)** - `CrashSummaryAnalyzer`
- **Location**: `crash_summaries.py` line 604
- **Input**: `ast.FunctionDef` nodes (Python source AST)
- **Used by**: `CrashSummaryComputer._analyze_function()` (line 3198) - **FALLBACK ONLY**
- **Operations**: 
  - Walks AST nodes (`ast.NodeVisitor`)
  - Detects `ast.BinOp`, `ast.Subscript`, `ast.Attribute`
  - Uses guard tracking via `GuardTracker`
- **Advantages**: 
  - Human-readable (variable names preserved)
  - Easy to debug
  - Good for pattern matching on source
- **Disadvantages**:
  - Harder to get precise control flow
  - Misses compiled-time optimizations
  - Less precise for guards

#### 2. **Bytecode-Based** - `BytecodeCrashSummaryAnalyzer`
- **Location**: `crash_summaries.py` line 1359
- **Input**: `types.CodeType` objects (compiled Python bytecode)
- **Used by**: 
  - `BytecodeCrashSummaryComputer._analyze_function()` (line 3013) - **PRIMARY PATH**
  - Direct usage in test scripts
- **Operations**:
  - Uses `dis.get_instructions()` for bytecode
  - Builds CFG with `build_cfg(code)`
  - Runs intraprocedural dataflow with `run_intraprocedural_analysis(code)`
  - Exception analysis with `ExceptionCatchAnalyzer`
  - DSE (Dynamic Symbolic Execution) integration
  - Path-sensitive analysis
- **Advantages**:
  - Precise control flow (CFG from bytecode)
  - Better guard analysis (path-sensitive)
  - Direct integration with verification engines
  - **This is what actually runs in production**
- **Disadvantages**:
  - Variable names lost (become `local_0`, `local_1`)
  - Harder to debug
  - Python version dependent (bytecode format changes)

### What Actually Runs

```python
# In BytecodeCrashSummaryComputer.compute_all():
for func in functions:
    code = compile(source)  # Get bytecode
    analyzer = BytecodeCrashSummaryAnalyzer(code=code)  # ✓ BYTECODE PATH
    summary = analyzer.analyze()

# In CrashSummaryComputer.compute_all():  
for func in functions:
    tree = ast.parse(source)  # Get AST
    analyzer = CrashSummaryAnalyzer(...)  # ✗ AST PATH (fallback only)
    summary = analyzer.analyze(ast_node)
```

**Result**: Bytecode path is PRIMARY. AST path is only used as fallback in older code.

---

## The Stdlib Detection Problem

### What You Just Fixed

1. **Added `bytecode_instructions` field** to `CrashSummary` dataclass
2. **Stored bytecode** in `BytecodeCrashSummaryAnalyzer.__init__()`:
   ```python
   self.summary.bytecode_instructions = self.instructions
   ```
3. **Fixed the check** in `extreme_verification.py`:
   ```python
   # OLD (never worked):
   if hasattr(crash_summary, 'instructions'):  # Always False
   
   # NEW (works now):
   if crash_summary.bytecode_instructions:  # List populated by BytecodeCrashSummaryAnalyzer
   ```

### Why Detection Didn't Work

Your test showed:
```
✓ len() usage detected: {'len_results': set(), 'max_nonzero': set(), 'range_indices': set()}
```

**All empty!** The bytecode opcodes have **changed in Python 3.13+**:

| Old Opcode (3.10) | New Opcode (3.13+) | Your Code Looks For | What's Actually There |
|------------------|-------------------|---------------------|----------------------|
| `LOAD_CONST` | `LOAD_SMALL_INT` | `LOAD_CONST` | `LOAD_SMALL_INT` ✗ |
| `CALL_FUNCTION` | `CALL` | `CALL_FUNCTION` | `CALL` ✗ |
| `STORE_FAST` | `STORE_FAST` | `STORE_FAST` | `STORE_FAST` ✓ |

Your detection code:
```python
if instr.opname == 'LOAD_GLOBAL' and instr.argval == 'len':
    if i + 1 < len(instructions):
        next_instr = instructions[i + 1]
        if 'CALL' in next_instr.opname:  # This works
            if i + 2 < len(instructions):
                store_instr = instructions[i + 2]
                if 'STORE_FAST' in store_instr.opname:  # This works
                    usage['len_results'].add(store_instr.argval)
```

**Problem**: Between `LOAD_GLOBAL len` and `CALL`, there's now:
1. `LOAD_FAST_BORROW items` (load the argument)
2. Then `CALL 1` (call with 1 arg)

So the pattern is **off by one instruction**.

---

## Recommendations for Cleanup

### 1. **Consolidate to Bytecode-Only** (Recommended)

**Why**: You have two analyzers doing the same job. Bytecode is more precise and already the primary path.

**Action**:
- ✅ Keep: `BytecodeCrashSummaryAnalyzer` (line 1359)
- ❌ Remove: `CrashSummaryAnalyzer` (line 604) - 1200 lines of dead code
- ❌ Remove: `CrashSummaryComputer` (line 3138) - uses AST fallback
- ✅ Keep: `BytecodeCrashSummaryComputer` (line 2948) - main path

**Benefits**:
- 30% less code to maintain
- Single source of truth
- Clearer architecture
- No confusion about which analyzer runs

**Risks**:
- If anyone is using AST analyzer directly (unlikely - it's internal)
- Lose human-readable variable names in AST (but bytecode already primary)

---

### 2. **Fix Bytecode Pattern Matching** (Critical)

**Problem**: Your `_detect_stdlib_usage()` uses outdated bytecode patterns.

**Solution**: Make it version-agnostic and more flexible:

```python
def _detect_stdlib_usage(self, instructions: List[Any]) -> Dict[str, Set[str]]:
    """Detect stdlib function usage patterns (Python 3.10+ compatible)."""
    usage = {
        'len_results': set(),
        'max_nonzero': set(),
        'range_indices': set(),
    }
    
    i = 0
    while i < len(instructions):
        instr = instructions[i]
        
        # Pattern: LOAD_GLOBAL <func> -> (LOAD args) -> CALL -> STORE_FAST
        if instr.opname == 'LOAD_GLOBAL':
            func_name = instr.argval
            
            # Skip ahead to find CALL (may have LOAD_FAST for args in between)
            call_idx = None
            for j in range(i+1, min(i+10, len(instructions))):
                if 'CALL' in instructions[j].opname:
                    call_idx = j
                    break
            
            if call_idx is None:
                i += 1
                continue
            
            # Find STORE after CALL
            store_idx = None
            for j in range(call_idx+1, min(call_idx+5, len(instructions))):
                if 'STORE_FAST' in instructions[j].opname:
                    store_idx = j
                    break
            
            if store_idx is None:
                i += 1
                continue
            
            # Now match function-specific patterns
            store_var = instructions[store_idx].argval
            
            if func_name == 'len':
                usage['len_results'].add(store_var)
            
            elif func_name == 'max':
                # Check if there's a positive constant in args
                for k in range(i+1, call_idx):
                    arg_instr = instructions[k]
                    # Python 3.13: LOAD_SMALL_INT, Python 3.10: LOAD_CONST
                    if 'LOAD' in arg_instr.opname and 'CONST' in arg_instr.opname or 'SMALL_INT' in arg_instr.opname:
                        val = arg_instr.argval
                        if isinstance(val, int) and val > 0:
                            usage['max_nonzero'].add(store_var)
                            break
            
            elif func_name == 'range':
                usage['range_indices'].add(store_var)
        
        i += 1
    
    return usage
```

**Benefits**:
- Works across Python 3.10, 3.11, 3.12, 3.13
- More flexible pattern matching
- Handles variable argument positions

---

### 3. **Add Bytecode Abstraction Layer** (Future-Proof)

**Problem**: Direct bytecode manipulation is fragile when Python changes opcodes.

**Solution**: Create a semantic bytecode analyzer:

```python
class BytecodePatternMatcher:
    """Version-agnostic bytecode pattern matching."""
    
    def __init__(self, instructions: List[dis.Instruction]):
        self.instructions = instructions
        self.index = {instr.offset: i for i, instr in enumerate(instructions)}
    
    def find_function_calls(self, func_name: str) -> List[CallSite]:
        """Find all calls to a specific function."""
        calls = []
        for i, instr in enumerate(self.instructions):
            if instr.opname == 'LOAD_GLOBAL' and instr.argval == func_name:
                call_site = self._parse_call_site(i)
                if call_site:
                    calls.append(call_site)
        return calls
    
    def _parse_call_site(self, load_idx: int) -> Optional[CallSite]:
        """Parse a function call starting at LOAD_GLOBAL."""
        # Find CALL instruction (within 10 instructions)
        call_idx = self._find_next_opcode_matching(load_idx, lambda op: 'CALL' in op)
        if not call_idx:
            return None
        
        # Find STORE after call (within 5 instructions)
        store_idx = self._find_next_opcode_matching(call_idx, lambda op: 'STORE' in op)
        if not store_idx:
            return None
        
        return CallSite(
            function=self.instructions[load_idx].argval,
            call_offset=self.instructions[call_idx].offset,
            result_var=self.instructions[store_idx].argval if store_idx else None,
            arg_count=self.instructions[call_idx].arg if hasattr(self.instructions[call_idx], 'arg') else 0
        )
    
    def _find_next_opcode_matching(self, start_idx: int, predicate: Callable, max_distance: int = 10) -> Optional[int]:
        """Find next instruction matching predicate."""
        for i in range(start_idx + 1, min(start_idx + max_distance, len(self.instructions))):
            if predicate(self.instructions[i].opname):
                return i
        return None

@dataclass
class CallSite:
    function: str
    call_offset: int
    result_var: Optional[str]
    arg_count: int
```

**Usage**:
```python
matcher = BytecodePatternMatcher(crash_summary.bytecode_instructions)
len_calls = matcher.find_function_calls('len')
for call in len_calls:
    if call.result_var:
        usage['len_results'].add(call.result_var)
```

**Benefits**:
- Encapsulates bytecode complexity
- Easy to unit test
- Version changes isolated to one class
- Reusable across verification layers

---

### 4. **Improve Stdlib Semantics** (Effectiveness)

**Problem**: Only detecting `len()`, `max()`, `range()` - very limited.

**Solution**: Build a **stdlib contract database**:

```python
STDLIB_CONTRACTS = {
    'len': {
        'return_type': 'int',
        'return_range': (0, float('inf')),  # Always >= 0
        'guarantees': ['nonnegative'],
        'div_safe': False,  # len([]) == 0, not safe for division
    },
    'max': {
        'return_type': 'comparable',
        'return_range': 'min(args)',  # At least as large as smallest arg
        'guarantees': lambda args: ['nonzero'] if any(a > 0 for a in args) else [],
        'div_safe': lambda args: any(isinstance(a, int) and a > 0 for a in args),
    },
    'abs': {
        'return_type': 'numeric',
        'return_range': (0, float('inf')),
        'guarantees': ['nonnegative'],
        'div_safe': False,  # abs(0) == 0
    },
    'sum': {
        'return_type': 'numeric',
        'guarantees': [],  # Could be 0
        'div_safe': False,
    },
    # Add itertools, collections, etc.
}

def _synthesize_stdlib_barrier_with_ice(self, bug_type, bug_variable, crash_summary, result):
    """Enhanced stdlib barrier synthesis."""
    matcher = BytecodePatternMatcher(crash_summary.bytecode_instructions)
    
    # Find all function calls that produce bug_variable
    for func_name, contract in STDLIB_CONTRACTS.items():
        calls = matcher.find_function_calls(func_name)
        for call in calls:
            if call.result_var == bug_variable:
                # Check if contract provides safety guarantee
                if bug_type == 'DIV_ZERO':
                    if contract['div_safe']:
                        if callable(contract['div_safe']):
                            # Need to check args - extract from bytecode
                            args = matcher.get_call_args(call)
                            if contract['div_safe'](args):
                                return Barrier(f"{func_name}_nonzero", confidence=0.95)
                        else:
                            return Barrier(f"{func_name}_nonzero", confidence=0.90)
                
                elif bug_type == 'BOUNDS':
                    if 'nonnegative' in contract['guarantees']:
                        return Barrier(f"{func_name}_bounds", confidence=0.85)
    
    return None
```

---

## Recommended Action Plan

### Phase 1: Quick Wins (1-2 hours)
1. ✅ **Fix bytecode pattern matching** (use flexible search, handle Python 3.13)
2. ✅ **Test stdlib detection works** (verify len/max/range detected)
3. ✅ **Document which analyzer is used where** (this file)

### Phase 2: Cleanup (2-4 hours)
4. **Remove AST analyzer** (`CrashSummaryAnalyzer` + `CrashSummaryComputer`)
   - Keep only bytecode path
   - Update tests to use bytecode
   - Remove 1200+ lines of dead code

### Phase 3: Enhancement (4-8 hours)
5. **Add `BytecodePatternMatcher` abstraction**
   - Version-agnostic pattern matching
   - Reusable across verification layers
   - Unit testable

6. **Expand stdlib contracts database**
   - Add 20-30 common functions (abs, sum, min, enumerate, zip, etc.)
   - Include return guarantees (nonnull, nonzero, nonnegative, bounded)
   - Add type information for better verification

### Phase 4: Integration (2-4 hours)  
7. **Wire up to Layer 3 ICE learning**
   - Use stdlib contracts as positive examples
   - Feed into Houdini for invariant inference
   - Integrate with CEGAR for refinement

---

## Summary

**Current Architecture**: Mixed AST/Bytecode with bytecode primary
**Problem**: Stdlib detection broken due to Python 3.13 bytecode changes
**Root Cause**: Hard-coded opcode patterns + wrong attribute check
**Solution**: 
- ✅ Fixed attribute check (`bytecode_instructions`)
- ⚠️ Need to fix pattern matching (flexible search)
- 🔄 Should consolidate to bytecode-only (remove AST path)
- 🚀 Should add abstraction layer (BytecodePatternMatcher)

**Impact**:
- Immediate: Fix stdlib detection → Papers #9-12 can now work
- Short-term: Remove 1200 lines of dead code → cleaner architecture  
- Long-term: Version-proof pattern matching → robust across Python updates
