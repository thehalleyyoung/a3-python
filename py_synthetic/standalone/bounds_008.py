"""Standalone test for BOUNDS - matrix access."""

def get_cell(matrix, row, col):
    return matrix[row][col]

result = get_cell([[1, 2], [3, 4]], 5, 0)  # Row out of bounds
