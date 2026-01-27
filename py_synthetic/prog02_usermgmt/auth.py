"""Authentication utilities."""
import hashlib


def hash_password(password: str) -> str:
    """Hash a password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate(stored_hash: str, password: str) -> bool:
    """Check if password matches stored hash."""
    return hash_password(password) == stored_hash


def generate_token(user_id: int, secret: str) -> str:
    """Generate an auth token for a user."""
    data = f"{user_id}:{secret}"
    return hashlib.sha256(data.encode()).hexdigest()


def validate_token(token: str, user_id: int, secret: str) -> bool:
    """Validate an auth token."""
    expected = generate_token(user_id, secret)
    return token == expected


def get_secret_key(keys: list, index: int) -> str:
    """Get secret key by index."""
    # BUG: BOUNDS - no bounds check
    return keys[index]


def split_credentials(cred_string: str) -> tuple:
    """Split 'username:password' string."""
    parts = cred_string.split(":")
    # BUG: BOUNDS - assumes exactly 2 parts
    return (parts[0], parts[1])
