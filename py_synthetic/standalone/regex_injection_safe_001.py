"""Regex Injection: SAFE - Regex pattern is hardcoded"""

def search_logs_safe(search_term):
    """SAFE: Pattern is hardcoded, only search term from user"""
    import re
    logs = ["INFO: user logged in", "ERROR: timeout", "INFO: data saved"]
    pattern = re.compile(r'\b' + re.escape(search_term) + r'\b')  # SAFE: escaped
    return [log for log in logs if pattern.search(log)]

if __name__ == '__main__':
    import sys
    print(search_logs_safe(sys.argv[1]))
