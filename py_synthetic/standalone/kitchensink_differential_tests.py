#!/usr/bin/env python3
"""
Test cases designed to exercise kitchensink-unique detection capabilities.
These are bugs that BMC / stochastic replay / barrier analysis should find
but basic symbolic execution might miss.
"""

# ── Test 1: Loop-bounded division by zero ────────────────────────────────
# BMC should unroll the loop and find the div-by-zero at i=10
def countdown_divide(n):
    """Division by zero after loop countdown."""
    i = n
    while i > 0:
        i -= 1
    # i is now 0
    return 100 / i  # BUG: division by zero


# ── Test 2: Iterator protocol violation ──────────────────────────────────
# Kitchensink temporal/protocol analysis should detect double-close
class Resource:
    def __init__(self):
        self.closed = False
    def close(self):
        if self.closed:
            raise RuntimeError("Already closed")
        self.closed = True
    def read(self):
        if self.closed:
            raise RuntimeError("Read after close")
        return "data"

def use_after_close():
    """Use-after-close bug."""
    r = Resource()
    r.close()
    return r.read()  # BUG: use after close


# ── Test 3: Nested loop with invariant-dependent safety ──────────────────
# Invariant discovery (Houdini/ICE) needed to prove inner division safe
def matrix_normalize(matrix):
    """Normalizes rows but has div-zero when row sums to zero."""
    result = []
    for row in matrix:
        total = sum(row)
        # BUG: total could be 0 if all elements are 0
        normalized = [x / total for x in row]
        result.append(normalized)
    return result


# ── Test 4: Contract violation — precondition not checked ────────────────
def sqrt_approx(x):
    """Square root approximation that doesn't check negative input."""
    # BUG: No precondition check for x >= 0
    if x == 0:
        return 0
    guess = x / 2.0
    for _ in range(20):
        guess = (guess + x / guess) / 2.0
    return guess

# Calling with negative input triggers infinite loop / wrong result
result = sqrt_approx(-4)


# ── Test 5: Stochastic / probabilistic bug ───────────────────────────────
import random

def reservoir_sample(stream, k):
    """Reservoir sampling with off-by-one bug."""
    reservoir = []
    for i, item in enumerate(stream):
        if i < k:
            reservoir.append(item)
        else:
            # BUG: should be random.randint(0, i) not random.randint(0, i-1)
            j = random.randint(0, i - 1)
            if j < k:
                reservoir[j] = item
    return reservoir


# ── Test 6: Resource exhaustion — unbounded allocation ───────────────────
def read_all_lines(filename):
    """Reads all lines into memory without limit."""
    lines = []
    with open(filename) as f:
        for line in f:
            lines.append(line)  # BUG: Memory exhaustion for large files
    return lines


# ── Test 7: Type confusion in polymorphic dispatch ───────────────────────
def process_value(val):
    """Processes value but doesn't handle all types."""
    if isinstance(val, int):
        return val * 2
    elif isinstance(val, str):
        return val.upper()
    # BUG: No handling for list, dict, None, etc.
    return val.strip()  # AttributeError if val is not str-like


# ── Test 8: Data flow — unvalidated input reaching sensitive sink ────────
def build_query(user_input):
    """Builds SQL query with unvalidated user input."""
    # BUG: SQL injection — user_input flows directly to query
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query

def handle_request(request):
    name = request.get("name", "")
    return build_query(name)


# ── Test 9: Deep loop condition requiring BMC unrolling ──────────────────
def collatz_steps(n):
    """Collatz sequence — may not terminate for all inputs."""
    steps = 0
    while n != 1:
        if n % 2 == 0:
            n = n // 2
        else:
            n = 3 * n + 1
        steps += 1
        if steps > 10000:
            raise RuntimeError("Exceeded step limit")  # BUG: reachable for large n
    return steps


# ── Test 10: Incomplete error handling / unchecked return ────────────────
import os

def safe_read(path):
    """Reads file but doesn't handle missing file properly."""
    # BUG: os.path.exists is TOCTOU — file could be deleted between check and open
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    # Missing: no return value for the else case → returns None implicitly
