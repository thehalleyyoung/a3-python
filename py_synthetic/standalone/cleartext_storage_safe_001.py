"""Cleartext Storage: SAFE - Password hashed before storage"""

def register_user_safe(username, password):
    """SAFE: Password hashed before storage"""
    import json
    import hashlib
    users = {}
    hashed = hashlib.sha256(password.encode()).hexdigest()  # SAFE: Hashed
    users[username] = hashed
    with open('users.json', 'w') as f:
        json.dump(users, f)  # SAFE: Storing hashed password

if __name__ == '__main__':
    import sys
    register_user_safe(sys.argv[1], sys.argv[2])
