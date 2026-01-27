"""Flask Debug Mode: SAFE - Debug disabled"""

def create_app_safe():
    """SAFE: Debug mode disabled"""
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return "Hello"
    
    app.run(debug=False)  # SAFE: Debug disabled
    return app

if __name__ == '__main__':
    create_app_safe()
