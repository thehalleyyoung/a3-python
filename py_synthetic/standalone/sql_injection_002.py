"""SQL Injection: Interprocedural flow through helper function"""

def build_where_clause(field, value):
    """Helper that propagates taint"""
    return f"{field} = '{value}'"

def search_users(username):
    """BUG: SQL_INJECTION - Taint flows through build_where_clause"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    where = build_where_clause('name', username)
    query = f"SELECT * FROM users WHERE {where}"
    cursor.execute(query)  # BUG: username taint propagated through helper
    return cursor.fetchall()

if __name__ == '__main__':
    import sys
    search_users(sys.argv[1])
