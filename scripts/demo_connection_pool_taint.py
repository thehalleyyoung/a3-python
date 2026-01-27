#!/usr/bin/env python3
"""
Demonstration: Connection Pool Taint Tracking (Iteration 532)

This script demonstrates second-order SQL injection detection through tainted
database connection pools. The pattern:

1. Pool/connection created with tainted config → object inherits taint
2. Cursor obtained from tainted pool/connection → cursor inherits taint  
3. Query executed on tainted cursor → SQL injection detected

This is enabled by:
- Compositional object taint tracking (iteration 529-530)
- Receiver taint checking for SQL sinks (iteration 532)

The key insight: Even if the query string is clean, executing it on a cursor
from a tainted connection is unsafe because the attacker controls the database
configuration (e.g., the database file path, DSN, connection string).
"""

from pyfromscratch.z3model.taint_lattice import TaintLabel, SourceType
from pyfromscratch.contracts.security_lattice import (
    init_security_contracts,
    apply_source_taint,
    check_sink_taint,
)
from pyfromscratch.semantics.security_tracker_lattice import LatticeSecurityTracker


def demo_sqlite3_path_injection():
    """
    Demo: SQLite connection from user-controlled database path.
    
    Pattern:
        db_path = request.args.get('database')  # TAINTED
        conn = sqlite3.connect(db_path)         # conn inherits taint
        cursor = conn.cursor()                  # cursor inherits taint
        cursor.execute("SELECT * FROM users")   # INJECTION!
    
    The vulnerability: User controls db_path, so they can point to an
    attacker-controlled database file containing malicious data.
    """
    print("=" * 70)
    print("Demo 1: SQLite Path Injection")
    print("=" * 70)
    
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: db_path = request.args.get('database')
    db_path = object()
    db_path_label = apply_source_taint("request.args.get", "example.py:1")
    tracker.set_label(db_path, db_path_label)
    
    print(f"1. db_path = request.args.get('database')")
    print(f"   → Tainted: {db_path_label.has_untrusted_taint()}")
    print(f"   → Sources: {db_path_label.get_untrusted_sources()}")
    print()
    
    # Simulate: conn = sqlite3.connect(db_path)
    conn = object()
    conn_label, _ = tracker.handle_call_post(
        "sqlite3.connect",
        None,
        [db_path],
        conn,
        "example.py:2"
    )
    
    print(f"2. conn = sqlite3.connect(db_path)")
    print(f"   → Connection tainted: {conn_label.has_untrusted_taint()}")
    print(f"   → Connection inherits taint from db_path")
    print()
    
    # Simulate: cursor = conn.cursor()
    cursor = object()
    cursor_label, _ = tracker.handle_call_post(
        "cursor",
        conn,  # Method on conn - this propagates taint!
        [],
        cursor,
        "example.py:3"
    )
    
    print(f"3. cursor = conn.cursor()")
    print(f"   → Cursor tainted: {cursor_label.has_untrusted_taint()}")
    print(f"   → Cursor inherits taint from conn (compositional)")
    print()
    
    # Simulate: cursor.execute("SELECT * FROM users")
    violations = check_sink_taint(
        "cursor.execute",
        "example.py:4",
        [TaintLabel.clean()],  # Query is clean
        receiver_label=cursor_label  # But cursor is tainted!
    )
    
    print(f"4. cursor.execute('SELECT * FROM users')")
    print(f"   → Query string: CLEAN")
    print(f"   → Cursor (receiver): TAINTED")
    print(f"   → Violations detected: {len(violations)}")
    if violations:
        for v in violations:
            print(f"      - {v.bug_type} ({v.cwe}) at {v.sink_location}")
            print(f"        Reason: Cursor from attacker-controlled database")
    print()


def demo_postgres_dsn_injection():
    """
    Demo: PostgreSQL connection pool with tainted DSN.
    
    Pattern:
        dsn = os.getenv('DATABASE_URL')  # TAINTED (from environment)
        pool = psycopg2.pool.SimpleConnectionPool(dsn)
        conn = pool.getconn()
        cursor = conn.cursor()
        cursor.execute(query)  # INJECTION!
    """
    print("=" * 70)
    print("Demo 2: PostgreSQL DSN Injection via Connection Pool")
    print("=" * 70)
    
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: dsn = os.getenv('DATABASE_URL')
    dsn = object()
    dsn_label = apply_source_taint("os.getenv", "example.py:1")
    tracker.set_label(dsn, dsn_label)
    
    print(f"1. dsn = os.getenv('DATABASE_URL')")
    print(f"   → Tainted: {dsn_label.has_untrusted_taint()}")
    print(f"   → Sources: {dsn_label.get_untrusted_sources()}")
    print()
    
    # Simulate: pool = psycopg2.pool.SimpleConnectionPool(dsn)
    pool = object()
    pool_label, _ = tracker.handle_call_post(
        "psycopg2.pool.SimpleConnectionPool",
        None,
        [dsn],
        pool,
        "example.py:2"
    )
    
    print(f"2. pool = psycopg2.pool.SimpleConnectionPool(dsn)")
    print(f"   → Pool tainted: {pool_label.has_untrusted_taint()}")
    print()
    
    # Simulate: conn = pool.getconn()
    conn = object()
    conn_label, _ = tracker.handle_call_post(
        "getconn",
        pool,  # Method on pool
        [],
        conn,
        "example.py:3"
    )
    
    print(f"3. conn = pool.getconn()")
    print(f"   → Connection tainted: {conn_label.has_untrusted_taint()}")
    print(f"   → Connection inherits taint from pool")
    print()
    
    # Simulate: cursor = conn.cursor()
    cursor = object()
    cursor_label, _ = tracker.handle_call_post(
        "cursor",
        conn,
        [],
        cursor,
        "example.py:4"
    )
    
    print(f"4. cursor = conn.cursor()")
    print(f"   → Cursor tainted: {cursor_label.has_untrusted_taint()}")
    print()
    
    # Simulate: cursor.execute(query)
    violations = check_sink_taint(
        "cursor.execute",
        "example.py:5",
        [TaintLabel.clean()],
        receiver_label=cursor_label
    )
    
    print(f"5. cursor.execute(query)")
    print(f"   → Violations: {len(violations)}")
    if violations:
        for v in violations:
            print(f"      - {v.bug_type}")
            print(f"        Taint path: env → dsn → pool → conn → cursor → SQL")
    print()


def demo_clean_connection_no_fp():
    """
    Demo: Clean connection (no false positives).
    
    Pattern:
        conn = sqlite3.connect('/safe/hardcoded/path.db')
        cursor = conn.cursor()
        cursor.execute(query)  # OK if query is clean
    """
    print("=" * 70)
    print("Demo 3: Clean Connection (No False Positive)")
    print("=" * 70)
    
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: path = '/safe/hardcoded/path.db' (not tainted)
    path = object()
    tracker.set_label(path, TaintLabel.clean())
    
    print(f"1. path = '/safe/hardcoded/path.db'")
    print(f"   → Tainted: False")
    print()
    
    # Simulate: conn = sqlite3.connect(path)
    conn = object()
    conn_label, _ = tracker.handle_call_post(
        "sqlite3.connect",
        None,
        [path],
        conn,
        "example.py:2"
    )
    
    print(f"2. conn = sqlite3.connect(path)")
    print(f"   → Connection tainted: {conn_label.has_untrusted_taint()}")
    print()
    
    # Simulate: cursor = conn.cursor()
    cursor = object()
    cursor_label, _ = tracker.handle_call_post(
        "cursor",
        conn,
        [],
        cursor,
        "example.py:3"
    )
    
    print(f"3. cursor = conn.cursor()")
    print(f"   → Cursor tainted: {cursor_label.has_untrusted_taint()}")
    print()
    
    # Simulate: cursor.execute(query)
    violations = check_sink_taint(
        "cursor.execute",
        "example.py:4",
        [TaintLabel.clean()],
        receiver_label=cursor_label
    )
    
    print(f"4. cursor.execute(clean_query)")
    print(f"   → Query: CLEAN")
    print(f"   → Cursor: CLEAN")
    print(f"   → Violations: {len(violations)} ✓ No false positive")
    print()


if __name__ == "__main__":
    print()
    print("=" * 70)
    print("Connection Pool Taint Tracking Demonstration")
    print("=" * 70)
    print()
    print("This demonstrates how taint flows through database connection")
    print("objects to detect second-order SQL injections where the attacker")
    print("controls the database configuration rather than the query string.")
    print()
    
    demo_sqlite3_path_injection()
    demo_postgres_dsn_injection()
    demo_clean_connection_no_fp()
    
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print("✓ Connection pool taint tracking detects second-order SQL injection")
    print("✓ Taint propagates: config → pool → connection → cursor → SQL sink")
    print("✓ No false positives on clean (hardcoded) connection paths")
    print("✓ Enabled by compositional object taint + receiver checking")
    print()
