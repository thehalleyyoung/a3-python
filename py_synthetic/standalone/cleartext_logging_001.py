"""Cleartext Logging: Password logged in plain text"""

def login(username, password):
    """BUG: CLEARTEXT_LOGGING - Sensitive password logged"""
    import logging
    logging.info(f"Login attempt: {username} with password {password}")  # BUG
    # ... authentication logic ...
    return True

if __name__ == '__main__':
    import sys
    login(sys.argv[1], sys.argv[2])
