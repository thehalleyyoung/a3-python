"""Insecure Cookie: Cookie set without Secure flag"""

def set_session_cookie(response, session_id):
    """BUG: INSECURE_COOKIE - Cookie without Secure flag"""
    response.set_cookie('session', session_id)  # BUG: No secure=True
    return response

if __name__ == '__main__':
    # Mock response object for testing
    class Response:
        def set_cookie(self, name, value, **kwargs):
            print(f"Set cookie: {name}={value}, kwargs={kwargs}")
    
    resp = Response()
    set_session_cookie(resp, 'abc123')
