"""Database connection handling."""
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class Connection:
    connection_string: str
    is_open: bool = False
    pool_size: int = 10
    active_connections: List = None
    
    def __post_init__(self):
        if self.active_connections is None:
            self.active_connections = []
    
    def open(self):
        self.is_open = True
    
    def close(self):
        self.is_open = False
    
    def get_connection(self, index: int):
        """Get connection from pool."""
        # BUG: BOUNDS
        return self.active_connections[index]


class ConnectionPool:
    def __init__(self, size: int):
        self.size = size
        self.connections = []
        self.available = []
    
    def get(self) -> Connection:
        """Get available connection."""
        # BUG: BOUNDS - might be empty
        return self.available.pop(0)
    
    def release(self, conn: Connection):
        self.available.append(conn)
    
    def get_at(self, index: int) -> Connection:
        """Get connection at index."""
        # BUG: BOUNDS
        return self.connections[index]


def parse_connection_string(conn_str: str) -> dict:
    """Parse connection string into components."""
    parts = conn_str.split(";")
    result = {}
    for part in parts:
        # BUG: BOUNDS - assumes key=value format
        key_val = part.split("=")
        result[key_val[0]] = key_val[1]
    return result


def get_connection_param(params: dict, key: str) -> str:
    """Get connection parameter."""
    # BUG: NULL_PTR
    value = params.get(key)
    return value.strip()


def calculate_pool_utilization(active: int, total: int) -> float:
    """Calculate pool utilization."""
    # BUG: DIV_ZERO
    return active / total


def safe_parse_connection(conn_str: str) -> dict:
    """Safely parse connection string."""
    if not conn_str:
        return {}
    parts = conn_str.split(";")
    result = {}
    for part in parts:
        if "=" in part:
            key_val = part.split("=", 1)
            if len(key_val) == 2:
                result[key_val[0]] = key_val[1]
    return result
