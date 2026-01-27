"""
Demonstration of database cursor taint tracking (Iteration 529).

This script shows how taint propagates from connection strings through
cursors to query results, enabling detection of second-order SQL injections.
"""

from pyfromscratch.semantics.security_tracker_lattice import LatticeSecurityTracker
from pyfromscratch.z3model.taint_lattice import TaintLabel, SourceType


def demo_cursor_taint_tracking():
    """
    Demonstrate second-order SQL injection detection via cursor taint.
    
    Scenario: Database connection from tainted environment variable
              → cursor inherits taint
              → query results inherit taint
              → using results in new query → SQL_INJECTION detected
    """
    print("=" * 70)
    print("Database Cursor Taint Tracking Demo (Iteration 529)")
    print("=" * 70)
    print()
    
    tracker = LatticeSecurityTracker()
    
    # Step 1: Tainted connection string from environment
    print("Step 1: Get database URL from environment")
    print("  conn_str = os.environ.get('DB_URL')")
    conn_str = "env_db_url"
    conn_str_label = TaintLabel.from_untrusted_source(SourceType.ENVIRONMENT, "line:10")
    tracker.set_label(conn_str, conn_str_label)
    print(f"  → τ(conn_str) = {bin(conn_str_label.tau)} (ENVIRONMENT)")
    print()
    
    # Step 2: Connect with tainted connection string
    print("Step 2: Create database connection")
    print("  conn = sqlite3.connect(conn_str)")
    conn = "connection_object"
    conn_label, _ = tracker.handle_call_post(
        func_name="sqlite3.connect",
        func_ref=None,
        args=[conn_str],
        result=conn,
        location="line:11"
    )
    print(f"  → τ(conn) = {bin(conn_label.tau)} (inherited from conn_str)")
    print(f"  → Tainted? {conn_label.has_untrusted_taint()}")
    print()
    
    # Step 3: Create cursor from tainted connection
    print("Step 3: Create cursor from connection")
    print("  cursor = conn.cursor()")
    cursor = "cursor_object"
    cursor_label, _ = tracker.handle_call_post(
        func_name="connection.cursor",
        func_ref=conn,
        args=[],
        result=cursor,
        location="line:12"
    )
    print(f"  → τ(cursor) = {bin(cursor_label.tau)} (inherited from conn)")
    print(f"  → Tainted? {cursor_label.has_untrusted_taint()}")
    print()
    
    # Step 4: Fetch results from tainted cursor
    print("Step 4: Fetch query results")
    print("  results = cursor.fetchone()")
    results = "database_row"
    results_label, _ = tracker.handle_call_post(
        func_name="cursor.fetchone",
        func_ref=cursor,
        args=[],
        result=results,
        location="line:13"
    )
    print(f"  → τ(results) = {bin(results_label.tau)}")
    print(f"  → Sources: {results_label.get_untrusted_sources()}")
    print(f"  → Includes ENVIRONMENT? {SourceType.ENVIRONMENT in results_label.get_untrusted_sources()}")
    print(f"  → Includes DATABASE_RESULT? {SourceType.DATABASE_RESULT in results_label.get_untrusted_sources()}")
    print()
    
    # Step 5: Build query from tainted results
    print("Step 5: Build query from results")
    print("  query = f\"SELECT * FROM logs WHERE user = '{results[0]}'\"")
    query = "query_string"
    tracker.set_label(query, results_label)
    print(f"  → τ(query) = {bin(results_label.tau)} (inherited from results)")
    print()
    
    # Step 6: Execute tainted query - should detect SQL_INJECTION
    print("Step 6: Execute query")
    print("  cursor.execute(query)")
    violation = tracker.handle_call_pre(
        func_name="cursor.execute",
        args=[cursor, query],
        location="line:16",
        is_method_call=True
    )
    
    if violation:
        print(f"  → ✓ DETECTED: {violation.bug_type}")
        print(f"  → CWE: {violation.cwe}")
        print(f"  → Message: {violation.message}")
        print(f"  → Confidence: {violation.confidence}")
        print()
        print("SUCCESS: Second-order SQL injection detected!")
    else:
        print(f"  → ✗ NOT DETECTED")
        print()
        print("FAILED: Should have detected SQL_INJECTION")
    
    print("=" * 70)


if __name__ == "__main__":
    demo_cursor_taint_tracking()
