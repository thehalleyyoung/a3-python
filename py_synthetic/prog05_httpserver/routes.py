"""URL Routing utilities."""
from typing import Callable, Optional


class Router:
    def __init__(self):
        self.routes = {}
        self.route_list = []
    
    def add_route(self, path: str, handler: Callable):
        """Add a route."""
        self.routes[path] = handler
        self.route_list.append(path)
    
    def get_handler(self, path: str) -> Optional[Callable]:
        """Get handler for path."""
        return self.routes.get(path)
    
    def get_route_at(self, index: int) -> str:
        """Get route at index."""
        # BUG: BOUNDS
        return self.route_list[index]
    
    def remove_route(self, path: str):
        """Remove a route."""
        # BUG: NULL_PTR - accessing handler before checking existence
        handler = self.routes.get(path)
        handler.cleanup()  # Method call on None
        del self.routes[path]


def match_pattern(pattern: str, path: str) -> dict:
    """Match URL pattern and extract params."""
    pattern_parts = pattern.split("/")
    path_parts = path.split("/")
    
    params = {}
    for i, part in enumerate(pattern_parts):
        if part.startswith(":"):
            # BUG: BOUNDS - path might have fewer parts
            params[part[1:]] = path_parts[i]
    
    return params


def build_url(base: str, params: dict) -> str:
    """Build URL with query params."""
    if not params:
        return base
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{base}?{query}"


def parse_path_segments(path: str, index: int) -> str:
    """Get path segment at index."""
    segments = path.strip("/").split("/")
    # BUG: BOUNDS
    return segments[index]


def calculate_route_priority(pattern: str, static_weight: int) -> float:
    """Calculate route priority for matching."""
    dynamic_count = pattern.count(":")
    # BUG: DIV_ZERO if static_weight is 0
    return len(pattern) / static_weight - dynamic_count
