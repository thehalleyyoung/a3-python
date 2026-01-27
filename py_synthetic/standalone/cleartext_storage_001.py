"""Cleartext Storage: Password stored without hashing"""

def register_user(username, password):
    """BUG: CLEARTEXT_STORAGE - Password stored in plaintext"""
    import json
    users = {}
    users[username] = password  # BUG: No hashing
    with open('users.json', 'w') as f:
        json.dump(users, f)  # BUG: Writing sensitive data unhashed

if __name__ == '__main__':
    import sys
    register_user(sys.argv[1], sys.argv[2])
