# Why You Need Nonlinear Arithmetic: A Barrier Certificate Example

A division-by-zero safety proof where no linear invariant exists, but a quadratic barrier succeeds.

## The Code

```python
def process_after_rotation(x, y, n):
    # precondition: x*x + y*y >= 1
    c, s = 3/5, 4/5                    # 3-4-5 rotation (c²+s²=1)
    for _ in range(n):
        x, y = c*x - s*y, s*x + c*y   # rotation preserves x²+y²
    return 1.0 / (x*x + y*y)           # DIV_ZERO if x=y=0
```

**Question:** Is the division safe from `ZeroDivisionError`?

## Transition System

**State:** s = (x, y) ∈ ℝ²

**Initial states:** Init = { (x, y) : x² + y² ≥ 1 }

**Transition:** (x, y) ↦ (cx − sy, sx + cy) where c = 3/5, s = 4/5

**Unsafe states:** Unsafe = { (0, 0) }

## Why Linear Arithmetic Cannot Work

Any linear invariant has the form `ax + by ≥ c`, which defines a halfplane. But Init is the exterior of a disk — it wraps around the origin in every direction.

**No halfplane can contain the entire unit circle while excluding the origin.** For any `ax + by ≥ c > 0`, the point `(-a/√(a²+b²), -b/√(a²+b²))` is on the unit circle but violates the inequality.

This means intervals, octagons, polyhedra, linear templates, and CEGAR with linear predicates all provably fail.

## Quadratic Barrier Certificate

**B(x, y) = x² + y² − 1**

A barrier certificate must satisfy three conditions:

| Condition | Check | Result |
|-----------|-------|--------|
| **Init:** B(s) ≥ 0 on Init | x² + y² ≥ 1 ⟹ B = x² + y² − 1 ≥ 0 | ✓ |
| **Inductive:** B preserved by Trans | x'² + y'² = (c² + s²)(x² + y²) = x² + y², so B(s') = B(s) | ✓ |
| **Unsafe:** B(s) < 0 on Unsafe | x = y = 0 ⟹ B = −1 < 0 | ✓ |

**SOS certificate:** B = 1 · (x² + y² − 1) where the multiplier 1 = 1² is sum-of-squares. Inductiveness: B(s') − B(s) = 0 = 0². Separation: −B at Unsafe = 1 = 1².

## Punchline

The invariant x² + y² ≥ 1 is inherently degree 2. No conjunction of linear inequalities can describe the exterior of a circle. Every purely-linear technique fails on this program; the quadratic barrier succeeds.
