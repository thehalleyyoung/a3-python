"""Request handling utilities."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Request:
    method: str
    path: str
    headers: dict
    body: Optional[str] = None
    query_params: dict = None
    
    def __post_init__(self):
        if self.query_params is None:
            self.query_params = {}


class RequestHandler:
    def __init__(self, method: str):
        self.method = method
        self.middleware = []
    
    def add_middleware(self, mw):
        self.middleware.append(mw)
    
    def handle(self, request: Request):
        raise NotImplementedError


def parse_request(raw: str) -> Optional[Request]:
    """Parse raw HTTP request string."""
    if not raw:
        return None
    
    lines = raw.split("\n")
    # BUG: BOUNDS - assumes at least one line
    first_line = lines[0]
    parts = first_line.split(" ")
    # BUG: BOUNDS - assumes 3 parts (method, path, version)
    method = parts[0]
    path = parts[1]
    
    headers = {}
    for i in range(1, len(lines)):
        line = lines[i].strip()
        if not line:
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    
    return Request(method=method, path=path, headers=headers)


def get_query_param(request: Request, key: str):
    """Get query parameter."""
    # BUG: NULL_PTR - query_params.get returns None
    value = request.query_params.get(key)
    return value.lower()  # Fails if None


def parse_query_string(query: str) -> dict:
    """Parse query string into dict."""
    result = {}
    pairs = query.split("&")
    for pair in pairs:
        # BUG: BOUNDS - assumes key=value format
        parts = pair.split("=")
        result[parts[0]] = parts[1]
    return result


def safe_parse_query(query: str) -> dict:
    """Safely parse query string."""
    if not query:
        return {}
    result = {}
    pairs = query.split("&")
    for pair in pairs:
        parts = pair.split("=")
        if len(parts) >= 2:  # Safe check
            result[parts[0]] = parts[1]
    return result
