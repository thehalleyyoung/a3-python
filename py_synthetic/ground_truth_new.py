"""
Ground Truth Manifest for Expanded Synthetic Test Suite (68 programs)

This file defines expected analyzer behavior for each test case.
Format:
  - filename: Test program filename
  - expected_verdict: BUG | SAFE | UNKNOWN
  - bug_types: List of bug types that should be detected (if BUG)
  - description: What the test validates
"""

GROUND_TRUTH = {
    # SQL Injection Tests (6 programs)
    "sql_injection_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["SQL_INJECTION"],
        "description": "Direct string concatenation in SQL query"
    },
    "sql_injection_002.py": {
        "expected_verdict": "BUG",
        "bug_types": ["SQL_INJECTION"],
        "description": "Interprocedural flow through helper function"
    },
    "sql_injection_interprocedural_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["SQL_INJECTION"],
        "description": "Complex 4-hop interprocedural taint flow"
    },
    "sql_injection_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "Parameterized query - no injection possible"
    },
    
    # Command Injection Tests (5 programs)
    "command_injection_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["COMMAND_INJECTION"],
        "description": "Direct os.system with user input"
    },
    "command_injection_002.py": {
        "expected_verdict": "BUG",
        "bug_types": ["COMMAND_INJECTION"],
        "description": "subprocess.run with shell=True"
    },
    "command_injection_interprocedural_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["COMMAND_INJECTION"],
        "description": "Taint flow through CommandBuilder class"
    },
    "command_injection_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "subprocess without shell - no injection"
    },
    
    # Path Injection Tests (4 programs)
    "path_injection_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["PATH_INJECTION"],
        "description": "Direct file open with user input"
    },
    "path_injection_002.py": {
        "expected_verdict": "BUG",
        "bug_types": ["PATH_INJECTION"],
        "description": "Path traversal through os.path.join"
    },
    "path_injection_interprocedural_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["PATH_INJECTION"],
        "description": "Multi-level recursive path building"
    },
    
    # Cleartext Logging Tests (2 programs)
    "cleartext_logging_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["CLEARTEXT_LOGGING"],
        "description": "Password logged in plaintext"
    },
    "cleartext_logging_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "Password not included in logs"
    },
    
    # Cleartext Storage Tests (2 programs)
    "cleartext_storage_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["CLEARTEXT_STORAGE"],
        "description": "Password stored without hashing"
    },
    "cleartext_storage_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "Password hashed before storage"
    },
    
    # Weak Crypto Tests (2 programs)
    "weak_crypto_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["WEAK_CRYPTO"],
        "description": "MD5 used for password hashing"
    },
    "weak_crypto_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "bcrypt used for password hashing"
    },
    
    # XXE Tests (2 programs)
    "xxe_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["XXE"],
        "description": "XML parsing without XXE protection"
    },
    "xxe_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "defusedxml used for safe parsing"
    },
    
    # Insecure Cookie Tests (2 programs)
    "insecure_cookie_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["INSECURE_COOKIE"],
        "description": "Cookie without Secure flag"
    },
    "insecure_cookie_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "Cookie with Secure and HttpOnly flags"
    },
    
    # Cookie Injection Tests (1 program)
    "cookie_injection_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["COOKIE_INJECTION"],
        "description": "Tainted user input in cookie value"
    },
    
    # Regex Injection Tests (2 programs)
    "regex_injection_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["REGEX_INJECTION"],
        "description": "User input used as regex pattern"
    },
    "regex_injection_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "User input escaped before use in regex"
    },
    
    # Flask Debug Tests (2 programs)
    "flask_debug_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["FLASK_DEBUG"],
        "description": "Debug mode enabled in production"
    },
    "flask_debug_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "Debug mode disabled"
    },
    
    # TARSLIP Tests (2 programs)
    "tarslip_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["TARSLIP"],
        "description": "Unsafe tar extraction"
    },
    "tarslip_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "Validated tar extraction"
    },
    
    # ZIPSLIP Tests (2 programs)
    "zipslip_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["ZIPSLIP"],
        "description": "Unsafe zip extraction"
    },
    "zipslip_safe_001.py": {
        "expected_verdict": "SAFE",
        "bug_types": [],
        "description": "Validated zip extraction"
    },
    
    # Combined Bug Tests (1 program)
    "combined_sql_logging_001.py": {
        "expected_verdict": "BUG",
        "bug_types": ["SQL_INJECTION", "CLEARTEXT_LOGGING"],
        "description": "Multiple bugs: SQL injection AND cleartext logging"
    },
}

# Summary statistics
TOTAL_PROGRAMS = len(GROUND_TRUTH)
BUG_PROGRAMS = len([p for p, v in GROUND_TRUTH.items() if v["expected_verdict"] == "BUG"])
SAFE_PROGRAMS = len([p for p, v in GROUND_TRUTH.items() if v["expected_verdict"] == "SAFE"])

print(f"Total programs: {TOTAL_PROGRAMS}")
print(f"Expected BUG: {BUG_PROGRAMS}")
print(f"Expected SAFE: {SAFE_PROGRAMS}")
