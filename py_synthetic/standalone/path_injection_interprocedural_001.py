"""Complex Path Injection: Recursive directory traversal"""

def resolve_path(base, *parts):
    """Recursively builds path from parts"""
    import os
    result = base
    for part in parts:
        result = os.path.join(result, part)
    return result

def read_nested_file(dir1, dir2, filename):
    """BUG: Multi-level path injection"""
    import sys
    user_dir1 = sys.argv[1] if len(sys.argv) > 1 else "dir1"
    user_dir2 = sys.argv[2] if len(sys.argv) > 2 else "dir2"
    user_file = sys.argv[3] if len(sys.argv) > 3 else "file.txt"
    
    # All three parts are tainted
    path = resolve_path('/var/data', user_dir1, user_dir2, user_file)
    
    with open(path, 'r') as f:  # BUG: Can read arbitrary files
        return f.read()

if __name__ == '__main__':
    print(read_nested_file("a", "b", "c"))
