"""SQL Injection: Direct concatenation in single function"""

def query_user(username):
    """BUG: SQL_INJECTION - Direct string concatenation"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)  # BUG: Tainted value flows to SQL sink
    return cursor.fetchall()

if __name__ == '__main__':
    import sys
    query_user(sys.argv[1])
