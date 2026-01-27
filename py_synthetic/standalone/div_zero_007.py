"""Standalone test for DIV_ZERO - denominator computed."""

def normalize(values):
    total = sum(values)
    return [v / total for v in values]

result = normalize([0, 0, 0])  # Sum is 0
