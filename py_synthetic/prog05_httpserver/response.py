"""HTTP Response utilities."""
from dataclasses import dataclass


@dataclass
class Response:
    status_code: int
    headers: dict
    body: str
    
    def to_bytes(self) -> bytes:
        """Convert response to bytes for sending."""
        status_line = f"HTTP/1.1 {self.status_code}\r\n"
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in self.headers.items())
        return (status_line + header_lines + "\r\n\r\n" + self.body).encode()


def create_response(status: int, body: str, content_type: str = "text/html") -> Response:
    """Create a response with given parameters."""
    return Response(
        status_code=status,
        headers={"Content-Type": content_type, "Content-Length": str(len(body))},
        body=body
    )


def create_error_response(status: int, message: str) -> Response:
    """Create an error response."""
    return create_response(status, f"<h1>{status} - {message}</h1>")


def create_json_response(data: dict) -> Response:
    """Create JSON response."""
    import json
    body = json.dumps(data)
    return create_response(200, body, "application/json")


def get_header_value(response: Response, key: str) -> str:
    """Get response header value."""
    # BUG: NULL_PTR - get returns None
    value = response.headers.get(key)
    return value.upper()


def calculate_content_ratio(response: Response, total_size: int) -> float:
    """Calculate body/total ratio."""
    body_size = len(response.body)
    # BUG: DIV_ZERO - total_size could be 0
    return body_size / total_size


def get_response_from_cache(cache: list, index: int) -> Response:
    """Get cached response."""
    # BUG: BOUNDS
    return cache[index]


def safe_get_header(response: Response, key: str) -> str:
    """Safely get header value."""
    value = response.headers.get(key)
    if value is None:
        return ""
    return value
