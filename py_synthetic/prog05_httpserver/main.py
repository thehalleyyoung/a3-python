"""HTTP Server - main module."""
from request_handler import RequestHandler, parse_request
from response import Response, create_error_response
from routes import Router


class HTTPServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.router = Router()
        self.handlers = []
    
    def add_route(self, path: str, handler):
        self.router.add_route(path, handler)
    
    def get_handler(self, index: int):
        """Get handler by index."""
        # BUG: BOUNDS
        return self.handlers[index]
    
    def handle_request(self, raw_request: str) -> Response:
        """Handle incoming request."""
        request = parse_request(raw_request)
        # BUG: NULL_PTR - parse_request might return None
        handler = self.router.get_handler(request.path)
        if handler:
            return handler(request)
        return create_error_response(404, "Not Found")


def process_headers(headers: dict, key: str) -> str:
    """Get header value."""
    # BUG: NULL_PTR - get returns None
    value = headers.get(key)
    return value.strip()  # Will fail if None


def calculate_response_time(start: float, end: float, count: int) -> float:
    """Calculate average response time."""
    total = end - start
    # BUG: DIV_ZERO
    return total / count


def get_route_param(params: list, index: int) -> str:
    """Get route parameter by index."""
    # BUG: BOUNDS
    return params[index]


def safe_get_header(headers: dict, key: str, default: str = "") -> str:
    """Safely get header with default."""
    value = headers.get(key)
    if value is None:
        return default
    return value.strip()
