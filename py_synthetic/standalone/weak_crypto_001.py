"""Weak Crypto: Using MD5 for password hashing"""

def hash_password(password):
    """BUG: WEAK_CRYPTO - MD5 is broken for password hashing"""
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()  # BUG: MD5 is weak

def register(username, password):
    """BUG: Uses weak hashing"""
    hashed = hash_password(password)
    # Store hashed password...
    return hashed

if __name__ == '__main__':
    import sys
    print(register(sys.argv[1], sys.argv[2]))
