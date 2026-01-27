"""Test harness for user management - triggers buggy functions."""


def test_login_none_user():
    """Login with non-existent user - triggers NULL_PTR."""
    users = {}
    username = "nonexistent"
    password = "test"
    # Simulate: user = users.get(username) returns None
    user = users.get(username)
    # BUG: NULL_PTR - accessing attribute on None
    password_hash = user.password_hash  # Will raise AttributeError
    return password_hash


def test_get_user_info_oob():
    """Get user info with bad index - triggers BOUNDS."""
    user_list = []  # Empty list
    user_id = 0
    # BUG: BOUNDS
    user = user_list[user_id]
    return user


def test_delete_user_none():
    """Delete non-existent user - triggers NULL_PTR."""
    users = {}
    username = "nonexistent"
    user = users.get(username)
    # BUG: NULL_PTR - calling method on None
    user.deactivate()


def test_get_user_attribute_none():
    """Get attribute from None user - triggers NULL_PTR."""
    user = None
    # BUG: NULL_PTR
    value = getattr(user, "name", None)
    return value.lower() if value else None  # Actually this is safe


def test_get_nth_user_oob():
    """Get nth user with bad index - triggers BOUNDS."""
    users = []  # Empty
    n = 5
    # BUG: BOUNDS
    return users[n]


def test_get_secret_key_oob():
    """Get secret key with bad index - triggers BOUNDS."""
    keys = ["key1", "key2"]
    index = 10
    # BUG: BOUNDS
    return keys[index]


def test_split_credentials_short():
    """Split credentials without colon - triggers BOUNDS."""
    cred_string = "nocolon"  # No : separator
    parts = cred_string.split(":")
    # BUG: BOUNDS - only 1 part, accessing index 1
    return (parts[0], parts[1])


# Run tests
if __name__ == "__main__":
    try:
        test_login_none_user()
    except AttributeError:
        pass
