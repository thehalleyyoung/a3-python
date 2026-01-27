"""Insecure Cookie: SAFE - Cookie with Secure and HttpOnly flags"""

def set_session_cookie_safe(response, session_id):
    """SAFE: Cookie with proper security flags"""
    response.set_cookie('session', session_id, secure=True, httponly=True)  # SAFE
    return response

if __name__ == '__main__':
    # Mock response object for testing
    class Response:
        def set_cookie(self, name, value, **kwargs):
            print(f"Set cookie: {name}={value}, kwargs={kwargs}")
    
    resp = Response()
    set_session_cookie_safe(resp, 'abc123')
