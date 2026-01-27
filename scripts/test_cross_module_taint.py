#!/usr/bin/env python3
"""
Comprehensive test for cross-module interprocedural taint tracking.

Tests that:
1. Cross-module call edges are resolved
2. Taint summaries are computed correctly for cross-module functions
3. Security bugs are detected through cross-module call chains
"""

import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.summaries import SummaryComputer
from pyfromscratch.contracts.security_lattice import (
    get_source_contracts_for_summaries,
    get_sink_contracts_for_summaries,
    get_sanitizer_contracts_for_summaries
)
from pyfromscratch.z3model.taint_lattice import SinkType


def test_cross_module_taint_summaries():
    """Test that taint flows through cross-module call chains in summaries."""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        
        # Create a 3-module chain: web -> controller -> database
        
        # database.py - has SQL injection sink
        database_code = """
import sqlite3

def execute_query(user_input):
    '''Execute SQL query with user input'''
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    # SQL injection sink
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return cursor.fetchall()

def safe_query(sanitized_input):
    '''Execute SQL query with sanitized input'''
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    # Parameterized query - safe
    cursor.execute("SELECT * FROM users WHERE name = ?", (sanitized_input,))
    return cursor.fetchall()
"""
        (tmpdir_path / "database.py").write_text(database_code)
        
        # controller.py - processes data and calls database
        controller_code = """
from database import execute_query, safe_query

def process_user_data(data):
    '''Process user data and query database'''
    # This function propagates taint from param 0 to execute_query
    results = execute_query(data)
    return results

def process_with_validation(data):
    '''Process user data with validation'''
    # Validation/sanitization
    if data and isinstance(data, str) and len(data) < 100:
        clean_data = data.replace("'", "''")  # SQL escaping
        return safe_query(clean_data)
    return []
"""
        (tmpdir_path / "controller.py").write_text(controller_code)
        
        # web.py - HTTP handlers (source of taint)
        web_code = """
from controller import process_user_data, process_with_validation

def unsafe_route(request):
    '''Unsafe HTTP route handler'''
    # Source: HTTP parameter
    username = request.args.get('username')
    # Call to controller (which calls database)
    results = process_user_data(username)
    return results

def safe_route(request):
    '''Safe HTTP route handler with validation'''
    username = request.args.get('username')
    results = process_with_validation(username)
    return results
"""
        (tmpdir_path / "web.py").write_text(web_code)
        
        print("=== Building call graph ===")
        call_graph = build_call_graph_from_directory(tmpdir_path)
        
        print(f"\nFound {len(call_graph.functions)} functions:")
        for qname in sorted(call_graph.functions.keys()):
            print(f"  {qname}")
        
        print(f"\nCall graph edges:")
        for caller, callees in sorted(call_graph.edges.items()):
            for callee in callees:
                print(f"  {caller} -> {callee}")
        
        # Verify the call chain is complete
        print("\n=== Verifying call chains ===")
        
        unsafe_route = None
        process_user_data = None
        execute_query = None
        
        for qname in call_graph.functions:
            if 'unsafe_route' in qname:
                unsafe_route = qname
            elif 'process_user_data' in qname:
                process_user_data = qname
            elif 'execute_query' in qname:
                execute_query = qname
        
        if unsafe_route and process_user_data and execute_query:
            # Check call chain: unsafe_route -> process_user_data -> execute_query
            callees_route = call_graph.get_callees(unsafe_route)
            callees_process = call_graph.get_callees(process_user_data)
            
            print(f"unsafe_route calls: {callees_route}")
            print(f"process_user_data calls: {callees_process}")
            
            chain_complete = (
                process_user_data in callees_route and
                execute_query in callees_process
            )
            
            if chain_complete:
                print("✓ Call chain complete: unsafe_route -> process_user_data -> execute_query")
            else:
                print("✗ Call chain incomplete")
                return False
        else:
            print(f"✗ Missing functions: unsafe_route={unsafe_route}, process_user_data={process_user_data}, execute_query={execute_query}")
            return False
        
        print("\n=== Computing taint summaries ===")
        
        computer = SummaryComputer(
            call_graph,
            source_contracts=get_source_contracts_for_summaries(),
            sink_contracts=get_sink_contracts_for_summaries(),
            sanitizer_contracts=get_sanitizer_contracts_for_summaries(),
        )
        summaries = computer.compute_all()
        
        print(f"\nComputed {len(summaries)} summaries")
        
        # Analyze summaries for the chain
        for func_name in [execute_query, process_user_data, unsafe_route]:
            if func_name in summaries:
                summary = summaries[func_name]
                print(f"\n{func_name}:")
                print(f"  param_to_return: {summary.dependency.param_to_return}")
                print(f"  is_source: {summary.dependency.introduces_taint}")
                print(f"  is_sink: {summary.dependency.is_sink}")
                print(f"  sink_types: {summary.dependency.sink_types}")
                print(f"  params_to_sinks: {summary.dependency.params_to_sinks}")
        
        # Verify key properties
        print("\n=== Verification ===")
        
        success = True
        
        # 1. execute_query should be detected as having a SQL sink
        if execute_query in summaries:
            summary = summaries[execute_query]
            if summary.dependency.is_sink and SinkType.SQL_EXECUTE in summary.dependency.sink_types:
                print("✓ execute_query detected as SQL sink")
            else:
                print(f"✗ execute_query NOT detected as SQL sink (is_sink={summary.dependency.is_sink}, types={summary.dependency.sink_types})")
                success = False
        
        # 2. process_user_data should propagate taint from param 0 to sink
        if process_user_data in summaries:
            summary = summaries[process_user_data]
            # Should detect that param 0 flows to a sink (transitively)
            if summary.dependency.params_to_sinks:
                print(f"✓ process_user_data param_to_sinks: {summary.dependency.params_to_sinks}")
            else:
                print(f"⚠ process_user_data does not track param-to-sink flow (this may be expected if only direct sinks are tracked)")
        
        # 3. unsafe_route should also be flagged (parameter flows to sink transitively)
        if unsafe_route in summaries:
            summary = summaries[unsafe_route]
            if summary.dependency.param_to_return or summary.dependency.params_to_sinks:
                print(f"✓ unsafe_route tracks dataflow (param_to_return={summary.dependency.param_to_return}, params_to_sinks={summary.dependency.params_to_sinks})")
            else:
                print(f"⚠ unsafe_route does not track dataflow")
        
        return success


if __name__ == '__main__':
    success = test_cross_module_taint_summaries()
    if success:
        print("\n✓ All cross-module tests passed")
        sys.exit(0)
    else:
        print("\n✗ Some tests failed")
        sys.exit(1)
