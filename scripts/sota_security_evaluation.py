#!/usr/bin/env python
"""
SOTA Security Engine Evaluation Script.

Tests the SOTA engine against a set of security-focused test cases.
"""

import types
from pathlib import Path

from pyfromscratch.semantics.sota_intraprocedural import analyze_function_sota
from pyfromscratch.z3model.taint_lattice import SinkType


def compile_and_get_func(source: str, func_name: str = "test_func") -> types.CodeType:
    """Compile source and extract function code object."""
    code = compile(source, "<test>", "exec")
    for const in code.co_consts:
        if isinstance(const, types.CodeType) and const.co_name == func_name:
            return const
    raise ValueError(f"Function {func_name} not found")


# ============================================================================
# TEST CASES
# ============================================================================

SECURITY_TESTS = [
    # === SQL INJECTION ===
    {
        "name": "sql_concat_bug",
        "expected": "BUG",
        "sink_type": SinkType.SQL_EXECUTE,
        "source": '''
def test_func(user_id):
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
'''
    },
    {
        "name": "sql_format_bug",
        "expected": "BUG",
        "sink_type": SinkType.SQL_EXECUTE,
        "source": '''
def test_func(user_id):
    query = "SELECT * FROM users WHERE id={}".format(user_id)
    cursor.execute(query)
'''
    },
    {
        "name": "sql_fstring_bug",
        "expected": "BUG",
        "sink_type": SinkType.SQL_EXECUTE,
        "source": '''
def test_func(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
'''
    },
    
    # === COMMAND INJECTION ===
    {
        "name": "cmd_os_system_bug",
        "expected": "BUG",
        "sink_type": SinkType.COMMAND_SHELL,
        "source": '''
def test_func(cmd):
    import os
    os.system(cmd)
'''
    },
    {
        "name": "cmd_subprocess_bug",
        "expected": "BUG",
        "sink_type": SinkType.COMMAND_SHELL,
        "source": '''
def test_func(cmd):
    import subprocess
    subprocess.call(cmd, shell=True)
'''
    },
    
    # === CODE INJECTION ===
    {
        "name": "code_eval_bug",
        "expected": "BUG",
        "sink_type": SinkType.CODE_EVAL,
        "source": '''
def test_func(code):
    eval(code)
'''
    },
    {
        "name": "code_exec_bug",
        "expected": "BUG",
        "sink_type": SinkType.CODE_EVAL,
        "source": '''
def test_func(code):
    exec(code)
'''
    },
    
    # === PATH TRAVERSAL ===
    {
        "name": "path_open_bug",
        "expected": "BUG",
        "sink_type": SinkType.FILE_PATH,
        "source": '''
def test_func(filename):
    with open(filename) as f:
        return f.read()
'''
    },
    
    # === SAFE CASES ===
    {
        "name": "safe_no_taint",
        "expected": "SAFE",
        "source": '''
def test_func():
    query = "SELECT * FROM users WHERE id=1"
    cursor.execute(query)
'''
    },
    {
        "name": "safe_constant",
        "expected": "SAFE",
        "source": '''
def test_func(count):
    # count is not a suspicious name
    return count + 1
'''
    },
]


def run_evaluation():
    """Run all security tests and report results."""
    results = {
        "passed": 0,
        "failed": 0,
        "tests": []
    }
    
    print("=" * 60)
    print("SOTA SECURITY ENGINE EVALUATION")
    print("=" * 60)
    print()
    
    for test in SECURITY_TESTS:
        name = test["name"]
        expected = test["expected"]
        source = test["source"]
        sink_type = test.get("sink_type")
        
        try:
            code = compile_and_get_func(source)
            violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
            
            actual = "BUG" if violations else "SAFE"
            passed = (actual == expected)
            
            if passed:
                results["passed"] += 1
                status = "✓ PASS"
            else:
                results["failed"] += 1
                status = "✗ FAIL"
            
            # Additional check: correct sink type detected?
            if expected == "BUG" and violations and sink_type:
                detected_sink = violations[0].sink_type
                if detected_sink != sink_type:
                    status += f" (wrong sink: {detected_sink.name} != {sink_type.name})"
            
            print(f"{status}: {name}")
            print(f"       Expected: {expected}, Got: {actual}")
            if violations:
                print(f"       Violations: {[v.bug_type for v in violations]}")
            
            results["tests"].append({
                "name": name,
                "expected": expected,
                "actual": actual,
                "passed": passed,
                "violations": len(violations) if violations else 0,
            })
            
        except Exception as e:
            results["failed"] += 1
            print(f"✗ ERROR: {name}")
            print(f"       {type(e).__name__}: {e}")
            results["tests"].append({
                "name": name,
                "expected": expected,
                "actual": "ERROR",
                "passed": False,
                "error": str(e),
            })
    
    print()
    print("=" * 60)
    total = results["passed"] + results["failed"]
    print(f"RESULTS: {results['passed']}/{total} tests passed")
    print("=" * 60)
    
    return results


if __name__ == "__main__":
    run_evaluation()
