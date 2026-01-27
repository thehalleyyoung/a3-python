"""User management system - main module."""
from user import User, create_user, get_user_by_id
from auth import authenticate, hash_password


def register_user(username: str, password: str, users: dict) -> User:
    """Register a new user."""
    if username in users:
        raise ValueError("Username already exists")
    
    user = create_user(username, password)
    users[username] = user
    return user


def login(username: str, password: str, users: dict) -> User:
    """Login a user."""
    # BUG: NULL_PTR - get returns None if key not found
    user = users.get(username)
    # Using user without None check
    if authenticate(user.password_hash, password):
        return user
    raise ValueError("Invalid credentials")


def get_user_info(user_id: int, user_list: list) -> dict:
    """Get user info by ID."""
    # BUG: BOUNDS - no bounds check
    user = user_list[user_id]
    return {"name": user.username, "id": user.id}


def delete_user(username: str, users: dict) -> None:
    """Delete a user from the system."""
    # BUG: NULL_PTR - accessing methods on potentially None user
    user = users.get(username)
    user.deactivate()  # Will fail if user is None
    del users[username]


def list_active_users(users: dict) -> list:
    """List all active users."""
    return [u for u in users.values() if u.is_active]
