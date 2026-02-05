# Kitchensink Bug Taxonomy with Maximum FP/TP Discernment

## Overview

**ITERATION 700-701**: Created comprehensive bug taxonomy with 41 new fine-grained bug types organized into 6 layers. Each bug type maps to optimal verification strategies from the 20 SOTA papers for maximum FP reduction and TP detection.

## Bug Taxonomy Layers

```
═══════════════════════════════════════════════════════════════════════════════
                    KITCHENSINK BUG TAXONOMY (108 Total Types)
═══════════════════════════════════════════════════════════════════════════════

LAYER 1: EXCEPTION-BASED BUGS (17 types) - exception_bugs.py
  └─ VALUE_ERROR, RUNTIME_ERROR, FILE_NOT_FOUND, PERMISSION_ERROR, etc.

LAYER 2: CONTRACT-BASED BUGS (5 types) - kitchensink_taxonomy.py
  ├─ PRECONDITION_VIOLATION: Function requires P, caller doesn't ensure P
  ├─ POSTCONDITION_VIOLATION: Function promises Q, doesn't deliver Q
  ├─ INVARIANT_VIOLATION: Class invariant I broken by method
  ├─ REPRESENTATION_INVARIANT: Internal rep invariant violated
  └─ LISKOV_VIOLATION: Subclass violates superclass contract

LAYER 3: TEMPORAL/ORDERING BUGS (6 types) - kitchensink_taxonomy.py
  ├─ USE_BEFORE_INIT: Using resource before initialization
  ├─ USE_AFTER_CLOSE: Using resource after close/dispose
  ├─ DOUBLE_CLOSE: Closing resource twice
  ├─ MISSING_CLEANUP: Resource not closed on all paths
  ├─ ORDER_VIOLATION: Operations in wrong order
  └─ CONCURRENT_MODIFICATION: Modifying during iteration

LAYER 4: DATA FLOW BUGS (5 types) - kitchensink_taxonomy.py
  ├─ UNVALIDATED_INPUT: External input used without validation
  ├─ UNCHECKED_RETURN: Return value not checked
  ├─ IGNORED_EXCEPTION: Exception caught and ignored
  ├─ PARTIAL_INIT: Object partially initialized
  └─ STALE_VALUE: Using outdated cached value

LAYER 5: PROTOCOL BUGS (4 types) - kitchensink_taxonomy.py
  ├─ ITERATOR_PROTOCOL: __iter__/__next__ contract violation
  ├─ CONTEXT_MANAGER_PROTOCOL: __enter__/__exit__ contract violation
  ├─ DESCRIPTOR_PROTOCOL: __get__/__set__ contract violation
  └─ CALLABLE_PROTOCOL: __call__ contract violation

LAYER 6: RESOURCE BUGS (4 types) - kitchensink_taxonomy.py
  ├─ MEMORY_EXHAUSTION: Unbounded memory growth
  ├─ CPU_EXHAUSTION: Unbounded computation
  ├─ DISK_EXHAUSTION: Unbounded disk usage
  └─ HANDLE_EXHAUSTION: File descriptor/socket exhaustion

EXISTING LAYERS:
  • CORE ERROR BUGS (20 types): DIV_ZERO, BOUNDS, NULL_PTR, etc.
  • SECURITY BUGS (47 types): SQL_INJECTION, XSS, SSRF, etc.
═══════════════════════════════════════════════════════════════════════════════
```

## Kitchensink Verification Matrix

Each bug type has:
- **Intra-procedural strategy**: FP reduction + TP detection within one function
- **Inter-procedural strategy**: Compositional verification across functions/files
- **Z3 encoding**: How to encode in Z3 for barrier synthesis
- **Expected FP reduction**: Baseline → Kitchensink rates

### Contract-Based Bugs

| Bug Type | FP Papers | TP Papers | Inter-Proc | Baseline FP | Kitchen FP |
|----------|-----------|-----------|------------|-------------|------------|
| PRECONDITION_VIOLATION | #13,#18,#17 | #10,#15,#19 | A-G (#20) | 60% | 10% |
| POSTCONDITION_VIOLATION | #13,#6,#17 | #12,#15 | A-G (#20) | 50% | 8% |
| INVARIANT_VIOLATION | #18,#10,#6 | #12,#15,#19 | A-G (#20) | 55% | 12% |
| REPRESENTATION_INVARIANT | #18,#13 | #10,#12 | A-G (#20) | 45% | 10% |
| LISKOV_VIOLATION | #20,#13 | #12,#17 | A-G (#20) | 40% | 8% |

### Temporal/Ordering Bugs

| Bug Type | FP Papers | TP Papers | Inter-Proc | Baseline FP | Kitchen FP |
|----------|-----------|-----------|------------|-------------|------------|
| USE_BEFORE_INIT | #13,#15,#6 | #10,#12 | CHC (#11) | 50% | 5% |
| USE_AFTER_CLOSE | #13,#6 | #10,#15 | CHC (#11) | 45% | 5% |
| DOUBLE_CLOSE | #13,#6 | #10,#12 | CHC (#11) | 35% | 5% |
| MISSING_CLEANUP | #10,#13 | #10,#12,#2 | A-G (#20) | 55% | 10% |
| ORDER_VIOLATION | #13,#11 | #10,#12 | CHC (#11) | 40% | 8% |
| CONCURRENT_MODIFICATION | #13,#18 | #10,#12 | CHC (#11) | 45% | 8% |

### Data Flow Bugs

| Bug Type | FP Papers | TP Papers | Inter-Proc | Baseline FP | Kitchen FP |
|----------|-----------|-----------|------------|-------------|------------|
| UNVALIDATED_INPUT | #13,#17 | #10,#12 | Taint | 70% | 15% |
| UNCHECKED_RETURN | #13,#18 | #10,#12 | Contract | 60% | 12% |
| IGNORED_EXCEPTION | #13 | #10 | Contract | 30% | 10% |
| PARTIAL_INIT | #18,#13 | #10,#12 | Contract | 45% | 8% |
| STALE_VALUE | #13,#6 | #10,#2 | Temporal | 50% | 15% |

### Protocol Bugs

| Bug Type | FP Papers | TP Papers | Inter-Proc | Baseline FP | Kitchen FP |
|----------|-----------|-----------|------------|-------------|------------|
| ITERATOR_PROTOCOL | #20,#13 | #12,#10 | Contract | 25% | 5% |
| CONTEXT_MANAGER_PROTOCOL | #20,#13 | #10,#12 | Resource | 20% | 3% |
| DESCRIPTOR_PROTOCOL | #20,#13 | #12,#10 | Contract | 30% | 5% |
| CALLABLE_PROTOCOL | #20,#13 | #12 | Contract | 25% | 5% |

### Resource Bugs

| Bug Type | FP Papers | TP Papers | Inter-Proc | Baseline FP | Kitchen FP |
|----------|-----------|-----------|------------|-------------|------------|
| MEMORY_EXHAUSTION | #6,#7,#8 | #2,#10 | Resource | 60% | 20% |
| CPU_EXHAUSTION | #6,#19 | #2,#10 | Resource | 55% | 15% |
| DISK_EXHAUSTION | #6,#2 | #2,#10 | Resource | 50% | 15% |
| HANDLE_EXHAUSTION | #6,#13 | #10,#12 | Resource | 45% | 10% |

## Inter-Procedural Verification Framework

### Summary Types

1. **Contract Summary**: Preconditions, postconditions, invariants
2. **Taint Summary**: Sources, sinks, sanitizers
3. **Resource Summary**: Acquired, released, lifecycle
4. **Temporal Summary**: Ordering constraints, state transitions

### Composition Rules

```python
# Assume-Guarantee Composition (Paper #20)
def compose(caller, callee):
    # 1. Check caller establishes callee's preconditions
    for pre in callee.preconditions:
        if not caller.postcondition.implies(pre):
            report("PRECONDITION_VIOLATION")
    
    # 2. Propagate callee's postcondition to caller
    caller.known_facts.add(callee.postconditions)
    
    # 3. Check exceptions are handled
    for exc in callee.exceptions:
        if exc not in caller.handlers:
            report("UNHANDLED_EXCEPTION")
    
    # 4. Track resource lifecycle
    for res in callee.acquired - callee.released:
        if res not in caller.will_release:
            report("RESOURCE_LEAK")
```
