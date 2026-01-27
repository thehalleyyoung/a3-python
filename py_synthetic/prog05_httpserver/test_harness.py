"""Test harness for HTTP server - triggers buggy functions."""


def test_get_handler_oob():
    """Get handler at bad index - triggers BOUNDS."""
    handlers = []
    index = 0
    # BUG: BOUNDS
    return handlers[index]


def test_handle_request_none():
    """Handle request when parse returns None - triggers NULL_PTR."""
    class Request:
        path = "/test"
    
    raw_request = ""  # Empty, parse returns None
    request = None  # Simulating parse_request returning None
    # BUG: NULL_PTR
    path = request.path


def test_process_headers_none():
    """Process headers when key missing - triggers NULL_PTR."""
    headers = {}
    key = "Content-Type"
    value = headers.get(key)
    # BUG: NULL_PTR
    return value.strip()


def test_calculate_response_time_zero():
    """Calculate response time with zero count - triggers DIV_ZERO."""
    start = 0.0
    end = 1.0
    count = 0
    total = end - start
    # BUG: DIV_ZERO
    return total / count


def test_get_route_param_oob():
    """Get route param at bad index - triggers BOUNDS."""
    params = []
    index = 0
    # BUG: BOUNDS
    return params[index]


def test_parse_request_short():
    """Parse request with incomplete first line - triggers BOUNDS."""
    raw = "GET"  # Only method, no path or version
    lines = raw.split("\n")
    first_line = lines[0]
    parts = first_line.split(" ")
    # BUG: BOUNDS
    method = parts[0]
    path = parts[1]


def test_get_query_param_none():
    """Get query param when missing - triggers NULL_PTR."""
    query_params = {}
    key = "id"
    value = query_params.get(key)
    # BUG: NULL_PTR
    return value.lower()


def test_parse_query_string_no_equals():
    """Parse query without equals - triggers BOUNDS."""
    query = "keyonly"  # No =value
    pairs = query.split("&")
    for pair in pairs:
        parts = pair.split("=")
        # BUG: BOUNDS
        result = (parts[0], parts[1])


def test_get_header_value_none():
    """Get header value when missing - triggers NULL_PTR."""
    headers = {}
    key = "Authorization"
    value = headers.get(key)
    # BUG: NULL_PTR
    return value.upper()


def test_calculate_content_ratio_zero():
    """Calculate ratio with zero total - triggers DIV_ZERO."""
    body_size = 100
    total_size = 0
    # BUG: DIV_ZERO
    return body_size / total_size


def test_get_response_from_cache_oob():
    """Get cached response at bad index - triggers BOUNDS."""
    cache = []
    index = 0
    # BUG: BOUNDS
    return cache[index]


def test_get_route_at_oob():
    """Get route at bad index - triggers BOUNDS."""
    route_list = []
    index = 0
    # BUG: BOUNDS
    return route_list[index]


def test_remove_route_none():
    """Remove route that doesn't exist - triggers NULL_PTR."""
    routes = {}
    path = "/nonexistent"
    handler = routes.get(path)
    # BUG: NULL_PTR
    handler.cleanup()


def test_match_pattern_short_path():
    """Match pattern with shorter path - triggers BOUNDS."""
    pattern = "/users/:id/posts/:post_id"
    path = "/users/123"  # Missing posts/:post_id
    pattern_parts = pattern.split("/")
    path_parts = path.split("/")
    params = {}
    for i, part in enumerate(pattern_parts):
        if part.startswith(":"):
            # BUG: BOUNDS - path_parts[i] doesn't exist
            params[part[1:]] = path_parts[i]


def test_parse_path_segments_oob():
    """Parse path segment at bad index - triggers BOUNDS."""
    path = "/users"
    segments = path.strip("/").split("/")
    index = 5
    # BUG: BOUNDS
    return segments[index]


def test_calculate_route_priority_zero():
    """Calculate priority with zero weight - triggers DIV_ZERO."""
    pattern = "/users/:id"
    static_weight = 0
    dynamic_count = pattern.count(":")
    # BUG: DIV_ZERO
    return len(pattern) / static_weight - dynamic_count


# Run tests
if __name__ == "__main__":
    try:
        test_calculate_response_time_zero()
    except ZeroDivisionError:
        pass
