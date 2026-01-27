"""Command Injection: subprocess.run with shell=True"""

def execute_grep(pattern, filename):
    """BUG: COMMAND_INJECTION - subprocess with shell=True and tainted input"""
    import subprocess
    cmd = f"grep {pattern} {filename}"
    subprocess.run(cmd, shell=True)  # BUG: Both args tainted, shell=True

if __name__ == '__main__':
    import sys
    execute_grep(sys.argv[1], sys.argv[2])
