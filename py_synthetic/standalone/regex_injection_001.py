"""Regex Injection: User input used as regex pattern"""

def search_logs(pattern):
    """BUG: REGEX_INJECTION - User input used as regex"""
    import re
    logs = ["INFO: user logged in", "ERROR: timeout", "INFO: data saved"]
    compiled = re.compile(pattern)  # BUG: ReDoS possible
    return [log for log in logs if compiled.search(log)]

if __name__ == '__main__':
    import sys
    print(search_logs(sys.argv[1]))
