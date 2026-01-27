"""SQL Injection: SAFE - Proper parameterization"""

def query_user_safe(username):
    """SAFE: Uses parameterized query"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (username,))  # SAFE: Parameterized
    return cursor.fetchall()

if __name__ == '__main__':
    import sys
    query_user_safe(sys.argv[1])
