#!/usr/bin/env python3
"""
Test Barrier Theory and Deferred Constraint Propagation

Demonstrates how library contracts enable proving safety through
deferred barrier checking. For example:

    cos_sim = cosine_similarity(x, y)  # Returns value in [-1, 1]
    divisor = cos_sim - 3               # Interval: [-4, -2]
    result = 1 / divisor                # Division barrier: is 0 in [-4, -2]? NO!
    
The analyzer can PROVE the division is safe because:
1. cosine_similarity contract guarantees result ∈ [-1, 1]
2. Interval arithmetic: [-1, 1] - 3 = [-4, -2]
3. 0 ∉ [-4, -2], so division by zero is IMPOSSIBLE
"""

import sys
sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')

from pyfromscratch.contracts.base import (
    Interval,
    AbstractValue,
    AbstractValueTracker,
    LibraryContract,
    Nullability,
    Postcondition,
    BarrierResult,
    BarrierStrength,
    get_global_registry,
    register_contract,
)


def test_interval_arithmetic():
    """Test interval arithmetic operations."""
    print("=" * 70)
    print("TEST: Interval Arithmetic")
    print("=" * 70)
    
    # Cosine similarity range
    cos_range = Interval.cosine_similarity_range()
    print(f"\nCosine similarity range: {cos_range}")
    assert cos_range.min_val == -1.0
    assert cos_range.max_val == 1.0
    
    # Subtract 3: [-1, 1] - 3 = [-4, -2]
    shifted = cos_range - 3
    print(f"After subtracting 3: {shifted}")
    assert shifted.min_val == -4.0
    assert shifted.max_val == -2.0
    
    # Does it contain zero?
    print(f"Contains zero? {shifted.contains_zero()}")
    assert not shifted.contains_zero(), "[-4, -2] should not contain zero!"
    
    # Is it definitely non-zero?
    print(f"Definitely non-zero? {shifted.is_definitely_non_zero()}")
    assert shifted.is_definitely_non_zero()
    
    print("\n✓ Interval arithmetic tests passed!")
    return True


def test_interval_operations():
    """Test various interval operations."""
    print("\n" + "=" * 70)
    print("TEST: Interval Operations")
    print("=" * 70)
    
    # Unit interval [0, 1]
    unit = Interval.unit_interval()
    print(f"\nUnit interval: {unit}")
    
    # Add 2: [0, 1] + 2 = [2, 3]
    added = unit + 2
    print(f"[0, 1] + 2 = {added}")
    assert added.min_val == 2.0
    assert added.max_val == 3.0
    assert not added.contains_zero()
    
    # Multiply by -1: [0, 1] * -1 = [-1, 0]
    negated = unit * -1
    print(f"[0, 1] * -1 = {negated}")
    assert negated.min_val == -1.0
    assert negated.max_val == 0.0
    
    # Non-negative interval
    non_neg = Interval.non_negative()
    print(f"\nNon-negative: {non_neg}")
    assert non_neg.contains_zero()  # [0, ∞) contains 0
    
    # Positive interval (0, ∞)
    positive = Interval.positive()
    print(f"Positive: {positive}")
    assert not positive.contains_zero()  # (0, ∞) excludes 0
    
    # Sigmoid output [0, 1]
    sigmoid_out = Interval.between(0.0, 1.0)
    # Logit transformation: divide by (1 - sigmoid)
    # Since sigmoid ∈ [0, 1], (1 - sigmoid) ∈ [0, 1]
    # This CAN contain zero, so division would be unsafe
    one_minus = Interval.exactly(1) - sigmoid_out
    print(f"\n1 - sigmoid([0,1]) = {one_minus}")
    assert one_minus.contains_zero(), "(1 - sigmoid) can be zero at sigmoid=1"
    
    print("\n✓ Interval operations tests passed!")
    return True


def test_deferred_barrier_checking():
    """Test deferred barrier checking with cosine similarity."""
    print("\n" + "=" * 70)
    print("TEST: Deferred Barrier Checking")
    print("=" * 70)
    
    # Create a tracker
    tracker = AbstractValueTracker()
    
    # Simulate: cos_sim = cosine_similarity(x, y)
    # The contract tells us cos_sim ∈ [-1, 1]
    cos_sim = AbstractValue(
        name="cos_sim",
        interval=Interval.cosine_similarity_range(),
        nullability=Nullability.NEVER,
        source_contract="torch.nn.functional.cosine_similarity",
        barrier_strength=BarrierStrength.STRONG,
    )
    tracker.track("cos_sim", cos_sim)
    print(f"\ncos_sim from cosine_similarity: {cos_sim.interval}")
    
    # Simulate: divisor = cos_sim - 3
    divisor = tracker.apply_subtract(cos_sim, 3)
    divisor.name = "divisor"
    tracker.track("divisor", divisor)
    print(f"divisor = cos_sim - 3: {divisor.interval}")
    
    # Check division barrier: is 1/divisor safe?
    result = tracker.check_division_barrier(divisor)
    print(f"\nDivision barrier check: {result}")
    assert result == BarrierResult.DEFINITELY_SAFE, \
        f"Expected DEFINITELY_SAFE, got {result}"
    
    print("\n✓ Deferred barrier checking proved division is safe!")
    print("  Reasoning: cosine_similarity ∈ [-1,1], so cos_sim - 3 ∈ [-4,-2]")
    print("  Since 0 ∉ [-4,-2], division by zero is IMPOSSIBLE")
    
    return True


def test_unsafe_division():
    """Test that unsafe divisions are properly detected."""
    print("\n" + "=" * 70)
    print("TEST: Unsafe Division Detection")
    print("=" * 70)
    
    tracker = AbstractValueTracker()
    
    # Simulate: sigmoid_out ∈ [0, 1]
    sigmoid_out = AbstractValue(
        name="sigmoid_out",
        interval=Interval.unit_interval(),
        nullability=Nullability.NEVER,
    )
    
    # Simulate: divisor = sigmoid_out - 0.5
    # Result: [-0.5, 0.5] which CONTAINS zero!
    divisor = tracker.apply_subtract(sigmoid_out, 0.5)
    divisor.name = "divisor"
    print(f"\nsigmoid_out ∈ [0, 1]")
    print(f"divisor = sigmoid_out - 0.5: {divisor.interval}")
    print(f"Contains zero? {divisor.interval.contains_zero()}")
    
    # Check division barrier
    result = tracker.check_division_barrier(divisor)
    print(f"Division barrier check: {result}")
    assert result == BarrierResult.MAYBE_VIOLATED, \
        f"Expected MAYBE_VIOLATED, got {result}"
    
    print("\n✓ Correctly detected MAYBE_VIOLATED (potential div by zero)")
    print("  Because sigmoid - 0.5 ∈ [-0.5, 0.5] which contains 0")
    
    return True


def test_safe_patterns():
    """Test various patterns that should be proven safe."""
    print("\n" + "=" * 70)
    print("TEST: Safe Patterns")
    print("=" * 70)
    
    tracker = AbstractValueTracker()
    
    # Pattern 1: exp(x) is always positive, so safe to divide by
    print("\n1. exp(x) is always positive:")
    exp_x = AbstractValue(
        name="exp_x",
        interval=Interval.positive(),  # exp(x) > 0 always
    )
    result = tracker.check_division_barrier(exp_x)
    print(f"   exp(x) interval: {exp_x.interval}")
    print(f"   Division barrier: {result}")
    assert result == BarrierResult.DEFINITELY_SAFE
    
    # Pattern 2: x^2 + 1 is always >= 1, so safe to divide by
    print("\n2. x^2 + 1 >= 1:")
    # x^2 is in [0, ∞)
    x_squared = AbstractValue(name="x_squared", interval=Interval.non_negative())
    # x^2 + 1 is in [1, ∞)
    x_squared_plus_1 = tracker.apply_add(x_squared, 1)
    result = tracker.check_division_barrier(x_squared_plus_1)
    print(f"   x^2 ∈ [0, ∞), so x^2 + 1 ∈ {x_squared_plus_1.interval}")
    print(f"   Division barrier: {result}")
    assert result == BarrierResult.DEFINITELY_SAFE
    
    # Pattern 3: |x| + epsilon is always positive
    print("\n3. |x| + ε > 0:")
    abs_x = AbstractValue(name="abs_x", interval=Interval.non_negative())
    epsilon = 1e-8
    abs_plus_eps = tracker.apply_add(abs_x, epsilon)
    result = tracker.check_division_barrier(abs_plus_eps)
    print(f"   |x| + 1e-8 ∈ {abs_plus_eps.interval}")
    print(f"   Division barrier: {result}")
    assert result == BarrierResult.DEFINITELY_SAFE
    
    # Pattern 4: norm is non-negative but CAN be zero
    print("\n4. norm(x) can be zero (for zero vector):")
    norm_x = AbstractValue(name="norm_x", interval=Interval.non_negative())
    result = tracker.check_division_barrier(norm_x)
    print(f"   norm(x) ∈ {norm_x.interval}")
    print(f"   Division barrier: {result}")
    assert result == BarrierResult.MAYBE_VIOLATED
    
    print("\n✓ All safe/unsafe patterns correctly identified!")
    return True


def test_contract_integration():
    """Test that contracts properly propagate intervals."""
    print("\n" + "=" * 70)
    print("TEST: Contract Integration")
    print("=" * 70)
    
    from pyfromscratch.contracts.torch_contracts import register_torch_contracts
    
    # Register contracts
    count = register_torch_contracts()
    print(f"\nRegistered {count} torch contracts")
    
    registry = get_global_registry()
    
    # Check cosine similarity contract
    cos_contract = registry.get("torch.nn.functional.cosine_similarity")
    if cos_contract:
        print(f"\nFound: {cos_contract.get_full_name()}")
        print(f"  Return interval: {cos_contract.return_interval}")
        print(f"  Postconditions: {len(cos_contract.postconditions)}")
        
        # Create abstract value from contract
        dummy_args = []
        result = cos_contract.apply_to_abstract_value(dummy_args)
        print(f"  Applied to abstract value: {result.interval}")
        assert result.interval.min_val == -1.0
        assert result.interval.max_val == 1.0
    
    # Check sigmoid contract
    sigmoid_contract = registry.get("torch.sigmoid")
    if sigmoid_contract:
        print(f"\nFound: {sigmoid_contract.get_full_name()}")
        print(f"  Return interval: {sigmoid_contract.return_interval}")
    
    # Check exp contract
    exp_contract = registry.get("torch.exp")
    if exp_contract:
        print(f"\nFound: {exp_contract.get_full_name()}")
        print(f"  Return interval: {exp_contract.return_interval}")
        print(f"  Is positive? {exp_contract.return_interval.is_positive}")
    
    print("\n✓ Contract integration tests passed!")
    return True


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("BARRIER THEORY - DEFERRED CONSTRAINT PROPAGATION TESTS")
    print("=" * 70)
    
    tests = [
        test_interval_arithmetic,
        test_interval_operations,
        test_deferred_barrier_checking,
        test_unsafe_division,
        test_safe_patterns,
        test_contract_integration,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"\n✗ {test.__name__} failed!")
        except Exception as e:
            failed += 1
            print(f"\n✗ {test.__name__} raised exception: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\n✓ All barrier theory tests passed!")
        print("\nKey insight demonstrated:")
        print("  cosine_similarity(x, y) - 3 is PROVEN safe to divide by")
        print("  because interval analysis shows result ∈ [-4, -2]")
        print("  and 0 ∉ [-4, -2]")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
