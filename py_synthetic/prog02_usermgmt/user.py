"""User model and related functions."""
from dataclasses import dataclass
from auth import hash_password


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    is_active: bool = True
    
    def deactivate(self):
        self.is_active = False
    
    def activate(self):
        self.is_active = True


_user_counter = 0


def create_user(username: str, password: str) -> User:
    """Create a new user with hashed password."""
    global _user_counter
    _user_counter += 1
    return User(
        id=_user_counter,
        username=username,
        password_hash=hash_password(password)
    )


def get_user_by_id(user_id: int, users: list) -> User:
    """Find user by ID in list."""
    for user in users:
        if user.id == user_id:
            return user
    return None  # Returns None if not found - caller must check


def get_user_attribute(user: User, attr: str):
    """Get user attribute dynamically."""
    # BUG: NULL_PTR - user could be None
    return getattr(user, attr)


def get_nth_user(users: list, n: int) -> User:
    """Get nth user from list."""
    # BUG: BOUNDS - no check on n
    return users[n]


def safe_get_user(user_id: int, users: list) -> User:
    """Safely get user by ID with None handling."""
    user = get_user_by_id(user_id, users)
    if user is None:
        raise ValueError(f"User {user_id} not found")
    return user  # Safe: None case handled
