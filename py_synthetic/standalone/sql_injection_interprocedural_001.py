"""Complex Interprocedural SQL Injection: Multi-hop taint flow"""

def get_user_input():
    """Source: Returns user input"""
    import sys
    return sys.argv[1] if len(sys.argv) > 1 else "test"

def sanitize_input(data):
    """Fake sanitizer that doesn't actually sanitize"""
    # BUG: Claims to sanitize but doesn't
    return data.strip()

def build_filter(field, value):
    """Builds SQL filter clause"""
    return f"{field} = '{value}'"

def execute_query(table, filter_clause):
    """Executes SQL query"""
    import sqlite3
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM {table} WHERE {filter_clause}"
    cursor.execute(query)  # BUG: Taint flows through 4 functions
    return cursor.fetchall()

def search_users(search_term):
    """BUG: Complex interprocedural SQL injection"""
    user_input = get_user_input()
    sanitized = sanitize_input(user_input)  # Fake sanitization
    filter_expr = build_filter('name', sanitized)
    return execute_query('users', filter_expr)  # BUG: 4-hop taint flow

if __name__ == '__main__':
    print(search_users("test"))
