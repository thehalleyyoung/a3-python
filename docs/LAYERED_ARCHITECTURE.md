# 5-Layer Architecture with Explicit Dependencies

## Architecture Overview

The extreme verification system uses a **5-layer architecture** where each layer explicitly builds on the layers below it.

---

## Layer Dependencies

```
Layer 5 (Advanced)
    ↑ uses results from
Layer 4 (Learning)  
    ↑ uses results from
Layer 3 (Abstraction)
    ↑ uses results from
Layer 2 (Certificate Core)
    ↑ uses tools from
Layer 1 (Foundations)
```

---

## Layer 1: Foundations (4 papers)

**Purpose**: Core mathematical tools for SOS/SDP

**Components**:
- `SOSDecomposer` - Sum-of-squares decomposition
- `PutinarProver` - Putinar's positivstellensatz
- `LasserreHierarchySolver` - Moment relaxation
- `SparseSOSDecomposer` - Sparse SOS optimization

**Used By**: Layer 2

**Outputs**: SOS certificates, polynomial decompositions

---

## Layer 2: Certificate Core (4 papers)

**Purpose**: Barrier certificate synthesis

**Components**:
- `HybridBarrierSynthesizer` - Hybrid system barriers
- `StochasticBarrierSynthesizer` - Probabilistic barriers
- `SOSSafetyChecker` - Safety verification
- `SOSTOOLSFramework` - SOS optimization framework

**Uses**: Layer 1 foundations for SOS decomposition

**Used By**: Layers 3, 4, 5

**Outputs**: Barrier certificates B(x) ≥ 0

**Code Location**: `extreme_verification.py` Phase 3
```python
# Layer 2 explicitly uses Layer 1
synthesis_problem = self._build_synthesis_problem(...)
verification_result = self.unified_engine.verify(system, property_spec)
# ↑ orchestrates Layer 1 + Layer 2
```

---

## Layer 3: Abstraction (4 papers)

**Purpose**: Refinement through abstraction

**Components**:
- `CEGARLoop` - Counterexample-guided refinement
- `PredicateAbstraction` - Boolean abstraction
- `BooleanProgram` - Abstract program construction
- `LazyAbstraction` - On-demand refinement

**Uses**: Layer 2 barriers as refinement targets

**Used By**: Layers 4, 5

**Outputs**: Refined barriers, abstract counterexamples

**Code Location**: `extreme_verification.py` Phase 6
```python
# Layer 3 explicitly uses Layer 2
cegar_problem = {
    'method': 'cegar',
    'barriers': all_barriers,  # ← from Layer 2
    'abstraction_level': 'boolean',
}
cegar_result = self.unified_engine.verify(cegar_problem)
# ↑ uses Layer 2 barriers, produces refined barrier
```

---

## Layer 4: Learning (3 papers)

**Purpose**: Invariant inference from examples

**Components**:
- `ICELearner` - Learning from implications
- `HoudiniBarrierInference` - Annotation inference
- `SyGuSSynthesizer` - Syntax-guided synthesis

**Uses**:
- Layer 3: Abstractions guide learning
- Layer 2: Barriers seed candidates

**Used By**: Layer 5

**Outputs**: Learned invariants, refined annotations

**Code Location**: `extreme_verification.py` Phases 4-5
```python
# Layer 4 explicitly uses Layers 2+3
learning_problem = {
    'method': 'ice',
    'examples': ice_examples,  # ← from Layer 3 abstractions
    'initial_barriers': layer2_barriers,  # ← from Layer 2
}
learning_result = self.unified_engine.verify(learning_problem)
# ↑ uses abstraction-guided examples + Layer 2 barriers

houdini_problem = {
    'method': 'houdini',
    'initial_barriers': layer2_barriers + layer4_learned,  # ← builds on lower layers
}
```

---

## Layer 5: Advanced (4 papers)

**Purpose**: Strongest inductive proofs

**Components**:
- `IC3Engine` - Property-directed reachability
- `SpacerCHC` - Constrained Horn clauses
- `IMCVerifier` - Interpolation-based model checking
- `AssumeGuaranteeVerifier` - Compositional verification

**Uses**:
- Layer 4: Learned invariants as candidates
- Layer 3: Abstractions for state space
- Layer 2: Barriers as candidate invariants

**Outputs**: Inductive invariants (strongest proof)

**Code Location**: `extreme_verification.py` Phase 7
```python
# Layer 5 explicitly uses Layers 2+3+4
ic3_problem = {
    'method': 'ic3',
    'transition_system': transition_system,
    'candidate_invariants': [
        b.formula for b in result.synthesized_barriers
    ],  # ← from Layers 2+3+4
}
ic3_result = self.unified_engine.verify(ic3_problem)
# ↑ uses ALL lower layer results as seed invariants
```

---

## Data Flow Through Layers

### Example: Verifying `x / y` where `y` might be 0

**Input**: `bug_type='DIV_ZERO'`, `bug_variable='y'`

**Layer 1** (Foundations):
- Provides SOS decomposition tools
- Output: Mathematical primitives

**Layer 2** (Certificate Core):
- Uses Layer 1 to synthesize barrier: `B(y) = y² - ε`
- Proves: `B(y) ≥ 0 ⟹ y ≠ 0`
- Output: `layer2_barriers = [B(y)]`

**Layer 3** (Abstraction):
- Uses Layer 2 barrier to build predicate abstraction
- Abstracts: `y ≠ 0` becomes boolean predicate
- CEGAR refines if spurious counterexample
- Output: Refined barrier

**Layer 4** (Learning):
- Uses Layer 3 abstractions as training examples
- Uses Layer 2 barriers as seed candidates
- ICE learns: `y > 0 ∨ y < 0` from positive/negative examples
- Houdini refines annotations
- Output: `layer4_learned = [learned invariant]`

**Layer 5** (IC3):
- Uses barriers from Layers 2, 3, 4 as candidate invariants
- Constructs transition system for `y` evolution
- IC3 finds inductive invariant: `I(y) ⟹ y ≠ 0 ∧ I'(y')`
- Output: **Inductive proof** (strongest)

---

## Benefits of Explicit Layering

### 1. **Incremental Precision**
Each layer adds precision:
- Layer 2: Barrier exists
- Layer 3: Barrier is spurious-free
- Layer 4: Barrier is learnable
- Layer 5: Barrier is inductive

### 2. **Fault Isolation**
If Layer N fails, we still have results from Layers 1..N-1

### 3. **Optimization Opportunities**
- Cache Layer 2 barriers for reuse in Layers 3-5
- Skip Layer 5 if Layer 2 proves safety (faster)
- Use Layer 4 failures to guide Layer 3 refinement

### 4. **Compositionality**
Each layer is a standalone verification technique:
- Can run layers independently
- Can compare layer results
- Can explain which layer provided the proof

---

## Implementation Details

### Phase Execution Order

```python
# Phase 1: Dataflow/intervals (fast path)
# Phase 2: Guards (explicit checks)

# Phase 3: Layer 2 <- Layer 1
layer2_barriers = synthesize_barriers()

# Phase 4: Layer 4 <- Layer 3 + Layer 2
layer4_learned = ice_learning(layer2_barriers)

# Phase 5: Layer 4 <- Layer 2 + Layer 4
houdini_refine(layer2_barriers + layer4_learned)

# Phase 6: Layer 3 <- Layer 2
cegar_refine(layer2_barriers)

# Phase 7: Layer 5 <- Layers 2+3+4
ic3_verify(all_barriers_from_lower_layers)
```

### Result Accumulation

```python
result.synthesized_barriers = []

# Layer 2 adds barriers
result.synthesized_barriers += layer2_barriers

# Layer 4 adds learned invariants  
result.synthesized_barriers += layer4_learned

# Layer 3 adds refined barriers
if cegar_success:
    result.synthesized_barriers += [refined_barrier]

# Layer 5 uses ALL accumulated barriers
ic3_uses(result.synthesized_barriers)
```

---

## Verification Strength Hierarchy

```
Weakest ────────────────────────────────────────► Strongest

Phase 2    │  Phase 3   │  Phase 6   │  Phase 4  │  Phase 7
Guards     │  Layer 2   │  Layer 3   │  Layer 4  │  Layer 5
           │  SOS       │  CEGAR     │  Learning │  IC3
           │  Barrier   │  Refined   │  Learned  │  Inductive
           │            │  Barrier   │  Inv      │  Inv

Explicit   │  Exists    │  Spurious  │  Data     │  Induction
checks     │  barrier   │  -free     │  -driven  │  proof
```

---

## Statistics Tracking

Each layer tracks:
- Success rate
- Time taken
- Barriers produced
- Refinements performed

Example output:
```
[EXTREME] Layer 2 succeeded - barrier synthesized (15.3ms)
[EXTREME] Layer 4 Houdini succeeded - annotations refined (8.7ms)
[EXTREME] Layer 5 IC3 succeeded - inductive invariant found (42.1ms)

Total: 66.1ms
Proof strength: Inductive (Layer 5)
```

---

## Future Enhancements

1. **Parallel Layers**: Run Layers 2-4 in parallel, feed results to Layer 5
2. **Layer Selection**: Use ML to predict which layer will succeed fastest
3. **Incremental**: Cache Layer 2 results across function calls
4. **Portfolio**: Run all layers, pick first success (vs. sequential)
5. **Feedback**: Use Layer 5 failures to improve Layer 2 synthesis

---

## Conclusion

The explicit layer architecture ensures:
- ✅ **Every paper is used consistently**
- ✅ **Each layer builds on lower layers**
- ✅ **Dependencies are traceable**
- ✅ **Results accumulate progressively**
- ✅ **Strongest possible proofs** (Layer 5 inductive invariants)

This is a **proper integration** of 20 SOTA papers, not just a collection of tools.
