#!/usr/bin/env python3
"""
Demonstration of automatic template selection based on program structure.

This script shows how the program analysis module automatically detects
loop nesting and suggests appropriate barrier certificate templates.
"""

from pyfromscratch.barriers.program_analysis import (
    analyze_program_structure,
    print_program_analysis,
)


def demo_simple_code():
    """Demo: Simple linear code (no loops)."""
    print("=" * 70)
    print("DEMO 1: Simple Linear Code (No Loops)")
    print("=" * 70)
    
    code = compile("""
x = 0
y = x + 1
z = y * 2
""", "<demo1>", "exec")
    
    print_program_analysis(code)
    print()


def demo_single_loop():
    """Demo: Single for loop."""
    print("=" * 70)
    print("DEMO 2: Single For Loop")
    print("=" * 70)
    
    code = compile("""
total = 0
for i in range(10):
    total += i
""", "<demo2>", "exec")
    
    print_program_analysis(code)
    print()


def demo_nested_loops():
    """Demo: Nested for loops."""
    print("=" * 70)
    print("DEMO 3: Nested For Loops")
    print("=" * 70)
    
    code = compile("""
matrix_sum = 0
for i in range(10):
    for j in range(10):
        matrix_sum += i * j
""", "<demo3>", "exec")
    
    print_program_analysis(code)
    print()


def demo_triple_nested():
    """Demo: Triple nested loops."""
    print("=" * 70)
    print("DEMO 4: Triple Nested Loops")
    print("=" * 70)
    
    code = compile("""
tensor_sum = 0
for i in range(5):
    for j in range(5):
        for k in range(5):
            tensor_sum += i * j * k
""", "<demo4>", "exec")
    
    print_program_analysis(code)
    print()


def demo_sequential_loops():
    """Demo: Multiple sequential (non-nested) loops."""
    print("=" * 70)
    print("DEMO 5: Sequential Loops (Not Nested)")
    print("=" * 70)
    
    code = compile("""
x = 0
for i in range(10):
    x += 1

y = 0
for j in range(5):
    y += 2

z = 0
for k in range(3):
    z += 3
""", "<demo5>", "exec")
    
    print_program_analysis(code)
    print()


def demo_conditional_in_loop():
    """Demo: Loop with conditional branches."""
    print("=" * 70)
    print("DEMO 6: Loop with Conditional Branch")
    print("=" * 70)
    
    code = compile("""
count_even = 0
count_odd = 0
for i in range(20):
    if i % 2 == 0:
        count_even += 1
    else:
        count_odd += 1
""", "<demo6>", "exec")
    
    print_program_analysis(code)
    print()


def demo_while_loop():
    """Demo: While loop."""
    print("=" * 70)
    print("DEMO 7: While Loop")
    print("=" * 70)
    
    code = compile("""
x = 0
while x < 100:
    x += 1
""", "<demo7>", "exec")
    
    print_program_analysis(code)
    print()


def demo_complex_example():
    """Demo: More complex realistic example."""
    print("=" * 70)
    print("DEMO 8: Complex Realistic Example")
    print("=" * 70)
    
    code = compile("""
def bubble_sort(arr):
    n = len(arr)
    for i in range(n):
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]
    return arr
""", "<demo8>", "exec")
    
    print_program_analysis(code)
    print()


if __name__ == "__main__":
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 10 + "AUTOMATIC TEMPLATE SELECTION DEMO" + " " * 25 + "║")
    print("╚" + "═" * 68 + "╝")
    print("\n")
    
    demos = [
        demo_simple_code,
        demo_single_loop,
        demo_nested_loops,
        demo_triple_nested,
        demo_sequential_loops,
        demo_conditional_in_loop,
        demo_while_loop,
        demo_complex_example,
    ]
    
    for demo in demos:
        demo()
        input("Press Enter to continue...")
    
    print("\n")
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
The program structure analyzer automatically determines:

1. Loop Detection: Identifies JUMP_BACKWARD bytecode instructions
2. Nesting Analysis: Computes depth (1=single, 2=nested, 3=deeply nested)
3. Variable Tracking: Finds variables modified within loops
4. Complexity Scoring: Overall program complexity metric

Template Selection Strategy:
- No loops or simple single loop  → LINEAR template (degree 1)
- Multiple or nested loops        → QUADRATIC template (degree 2)  
- Deeply nested loops (3+ levels) → CUBIC template (degree 3)

This automatically guides CEGIS barrier synthesis to start with
appropriate template complexity, improving synthesis efficiency while
maintaining soundness (all barriers are still Z3-verified).
""")
    print("=" * 70)
