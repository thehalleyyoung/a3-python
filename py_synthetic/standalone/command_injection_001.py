"""Command Injection: Direct os.system with user input"""

def run_command(user_input):
    """BUG: COMMAND_INJECTION - Direct os.system with tainted input"""
    import os
    cmd = "ls " + user_input
    os.system(cmd)  # BUG: Shell injection possible

if __name__ == '__main__':
    import sys
    run_command(sys.argv[1])
