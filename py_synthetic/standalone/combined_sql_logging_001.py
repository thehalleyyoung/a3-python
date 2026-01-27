"""Combined Bugs: SQL injection AND cleartext logging"""

def log_query(query):
    """Logs the query"""
    import logging
    logging.info(f"Executing query: {query}")  # Logs tainted query

def execute_user_query(username, password):
    """BUG: Multiple issues - SQL injection AND cleartext logging"""
    import sys
    import sqlite3
    
    user = sys.argv[1] if len(sys.argv) > 1 else "admin"
    pwd = sys.argv[2] if len(sys.argv) > 2 else "secret"
    
    # BUG 1: SQL Injection
    query = f"SELECT * FROM users WHERE name='{user}' AND password='{pwd}'"
    
    # BUG 2: Cleartext logging of sensitive data
    log_query(query)  # Logs password in plaintext
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)  # BUG 3: Execute tainted query
    return cursor.fetchall()

if __name__ == '__main__':
    print(execute_user_query("admin", "secret"))
