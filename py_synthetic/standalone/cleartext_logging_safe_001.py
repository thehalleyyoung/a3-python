"""Cleartext Logging: SAFE - Password redacted"""

def login_safe(username, password):
    """SAFE: Password not logged"""
    import logging
    logging.info(f"Login attempt: {username}")  # SAFE: No password
    # ... authentication logic ...
    return True

if __name__ == '__main__':
    import sys
    login_safe(sys.argv[1], sys.argv[2])
