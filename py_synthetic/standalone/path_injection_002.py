"""Path Injection: Interprocedural flow through path builder"""

def build_path(base, filename):
    """Propagates taint from filename"""
    import os
    return os.path.join(base, filename)

def load_config(filename):
    """BUG: PATH_INJECTION - Taint flows through build_path"""
    path = build_path('/etc/configs', filename)
    with open(path, 'r') as f:  # BUG: filename can be '../../../etc/passwd'
        return f.read()

if __name__ == '__main__':
    import sys
    print(load_config(sys.argv[1]))
