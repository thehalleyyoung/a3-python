"""Command Injection: SAFE - subprocess without shell"""

def execute_safe(filename):
    """SAFE: Uses subprocess without shell=True"""
    import subprocess
    subprocess.run(['cat', filename], shell=False)  # SAFE: No shell parsing

if __name__ == '__main__':
    import sys
    execute_safe(sys.argv[1])
