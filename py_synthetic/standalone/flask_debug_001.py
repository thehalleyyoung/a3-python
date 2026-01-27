"""Flask Debug Mode: Debug enabled in production"""

def create_app():
    """BUG: FLASK_DEBUG - Debug mode enabled"""
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return "Hello"
    
    app.run(debug=True)  # BUG: Debug in production exposes sensitive info
    return app

if __name__ == '__main__':
    create_app()
