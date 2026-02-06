#!/usr/bin/env python3
"""Remove duplicate AST-based analyzer from crash_summaries.py"""

# Read the file
with open('pyfromscratch/semantics/crash_summaries.py', 'r') as f:
    lines = f.readlines()

# Remove lines 654-1421 (0-indexed: 653-1420)
new_lines = lines[:653] + lines[1420:]

# Write back
with open('pyfromscratch/semantics/crash_summaries.py', 'w') as f:
    f.writelines(new_lines)

print(f"Removed {1420-653} lines")
print(f"Old line count: {len(lines)}")
print(f"New line count: {len(new_lines)}")
