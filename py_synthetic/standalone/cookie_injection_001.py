"""Cookie Injection: User input in cookie name"""

def set_user_cookie(response, cookie_name):
    """BUG: COOKIE_INJECTION - Tainted cookie name allows header injection"""
    response.set_cookie(cookie_name, 'static_value')  # BUG: cookie_name is tainted
    return response

if __name__ == '__main__':
    import sys
    class Response:
        def set_cookie(self, name, value, **kwargs):
            print(f"Set cookie: {name}={value}")
    
    resp = Response()
    # Attacker could inject: "evil\r\nSet-Cookie: admin=true"
    set_user_cookie(resp, sys.argv[1])
