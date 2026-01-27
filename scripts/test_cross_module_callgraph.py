#!/usr/bin/env python3
"""
Test script to demonstrate cross-module call graph resolution.
"""

import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory


def test_cross_module_resolution():
    """Test that cross-module imports are resolved into edges."""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        
        # Create module_a.py
        module_a_code = """
def source_func():
    '''Function that returns tainted data'''
    import os
    return os.environ.get('USER_INPUT')
"""
        (tmpdir_path / "module_a.py").write_text(module_a_code)
        
        # Create module_b.py that imports from module_a
        module_b_code = """
from module_a import source_func
import sqlite3

def process_data():
    '''Function that processes data from module_a'''
    data = source_func()  # Cross-module call
    
    # Sink: SQL injection
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{data}'")
    return cursor.fetchall()
"""
        (tmpdir_path / "module_b.py").write_text(module_b_code)
        
        print(f"Created test modules in {tmpdir_path}")
        print("\n=== Building call graph ===")
        
        # Build call graph
        call_graph = build_call_graph_from_directory(tmpdir_path)
        
        print(f"\nFound {len(call_graph.functions)} functions:")
        for qname in sorted(call_graph.functions.keys()):
            print(f"  - {qname}")
        
        print(f"\nFound {sum(len(v) for v in call_graph.edges.values())} internal edges:")
        for caller, callees in sorted(call_graph.edges.items()):
            for callee in callees:
                print(f"  {caller} -> {callee}")
        
        print(f"\nFound {sum(len(v) for v in call_graph.external_calls.values())} external calls:")
        for caller, callees in sorted(call_graph.external_calls.items()):
            for callee in callees:
                print(f"  {caller} -> {callee} (external)")
        
        # Check specific expectations
        print("\n=== Analysis ===")
        
        process_func = None
        source_func_name = None
        
        for qname in call_graph.functions:
            if 'process_data' in qname:
                process_func = qname
            if 'source_func' in qname:
                source_func_name = qname
        
        if process_func and source_func_name:
            print(f"Found process_data: {process_func}")
            print(f"Found source_func: {source_func_name}")
            
            # Check if edge exists
            callees = call_graph.get_callees(process_func)
            external = call_graph.external_calls.get(process_func, set())
            
            print(f"\nprocess_data calls:")
            print(f"  Internal: {callees}")
            print(f"  External: {external}")
            
            # The KEY ISSUE: cross-module calls are currently tracked as "external"
            # but should be resolved to internal edges when both functions are in the project
            
            if source_func_name in callees:
                print(f"\n✓ SUCCESS: Cross-module edge resolved correctly")
                print(f"  {process_func} -> {source_func_name}")
            elif 'source_func' in str(external) or 'module_a.source_func' in str(external):
                print(f"\n⚠ LIMITATION: Cross-module call tracked as external")
                print(f"  This prevents interprocedural taint tracking from working")
                print(f"  NEED: Resolve 'module_a.source_func' to actual function in call graph")
            else:
                print(f"\n✗ PROBLEM: Cross-module call not tracked at all")
        else:
            print(f"Could not find expected functions")
            print(f"  process_func: {process_func}")
            print(f"  source_func: {source_func_name}")


if __name__ == '__main__':
    test_cross_module_resolution()
