"""Weak Crypto: SAFE - Using bcrypt for password hashing"""

def hash_password_safe(password):
    """SAFE: Uses bcrypt which is designed for passwords"""
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())  # SAFE

def register_safe(username, password):
    """SAFE: Uses strong hashing"""
    hashed = hash_password_safe(password)
    # Store hashed password...
    return hashed

if __name__ == '__main__':
    import sys
    print(register_safe(sys.argv[1], sys.argv[2]))
