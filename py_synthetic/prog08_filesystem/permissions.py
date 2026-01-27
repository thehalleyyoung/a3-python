"""Permission handling module."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Permission:
    read: bool
    write: bool
    execute: bool


@dataclass
class FilePermissions:
    owner: str
    group: str
    owner_perms: Permission
    group_perms: Permission
    other_perms: Permission


def check_permission(perms: FilePermissions, user: str, action: str) -> bool:
    """Check if user has permission for action."""
    if user == perms.owner:
        p = perms.owner_perms
    else:
        p = perms.other_perms
    
    if action == "read":
        return p.read
    elif action == "write":
        return p.write
    elif action == "execute":
        return p.execute
    return False


def get_owner(path: str, file_map: dict) -> str:
    """Get file owner."""
    # BUG: NULL_PTR
    perms = file_map.get(path)
    return perms.owner


def get_permission_at(perm_list: list, index: int) -> Permission:
    """Get permission at index."""
    # BUG: BOUNDS
    return perm_list[index]


def parse_permission_string(perm_str: str, pos: int) -> str:
    """Parse permission character at position."""
    # BUG: BOUNDS
    return perm_str[pos]


def calculate_permission_ratio(allowed: int, total: int) -> float:
    """Calculate ratio of allowed operations."""
    # BUG: DIV_ZERO
    return allowed / total


def get_group_members(groups: dict, group_name: str) -> list:
    """Get members of a group."""
    # BUG: NULL_PTR
    members = groups.get(group_name)
    return members.copy()  # Method on None


def safe_get_owner(path: str, file_map: dict) -> Optional[str]:
    """Safely get file owner."""
    perms = file_map.get(path)
    if perms is None:
        return None
    return perms.owner
