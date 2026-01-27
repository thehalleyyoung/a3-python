"""Path Injection: Direct file open with user input"""

def read_file(filepath):
    """BUG: PATH_INJECTION - No validation on filepath"""
    with open(filepath, 'r') as f:  # BUG: Can read arbitrary files
        return f.read()

if __name__ == '__main__':
    import sys
    print(read_file(sys.argv[1]))
