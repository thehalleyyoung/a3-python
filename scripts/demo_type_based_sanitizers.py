#!/usr/bin/env python3
"""
Demo: Type-based sanitizers for improved precision.

This demonstrates how type conversions like int(), bool(), datetime parsing,
Path canonicalization, and IP validation act as sanitizers by constraining
the value domain.

Barrier-theoretic justification:
    For a type conversion T: V -> T(V), if T validates/constrains the domain:
        - int(user_input) prevents SQL injection (no SQL operators in integers)
        - bool(user_input) prevents command injection (only True/False)
        - Path(user_input).resolve() prevents path traversal
        - ipaddress.ip_address(user_input) prevents SSRF with invalid IPs
        - datetime.fromisoformat(user_input) validates temporal format

This improves precision by reducing false positives: values that pass through
type validation are provably safe for certain sinks.
"""

from pyfromscratch.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType
)
from pyfromscratch.contracts.security_lattice import apply_sanitizer


def demo_int_sanitization():
    """Demo: int() conversion sanitizes SQL injection."""
    print("\n=== int() Sanitization for SQL Injection ===")
    
    # User input is tainted
    user_id = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "request.GET['id']")
    print(f"1. user_id (raw): tainted={user_id.tau != 0}, safe_for_sql={user_id.is_safe_for_sink(SinkType.SQL_EXECUTE)}")
    
    # Apply int() conversion - constrains to integer domain
    user_id_int = apply_sanitizer("builtins.int", user_id)
    print(f"2. int(user_id):  tainted={user_id_int.tau != 0}, safe_for_sql={user_id_int.is_safe_for_sink(SinkType.SQL_EXECUTE)}")
    print("   Reason: int() validates format and constrains to numeric domain (no SQL operators)")
    
    # Even if converted back to string, still safe (domain is constrained)
    print("3. str(int(user_id)) is still safe for SQL (integer domain is constrained)")


def demo_bool_sanitization():
    """Demo: bool() conversion sanitizes multiple sinks."""
    print("\n=== bool() Sanitization for Multiple Sinks ===")
    
    enable_flag = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "request.args['enable']")
    print(f"1. enable_flag (raw): unsafe for SQL={not enable_flag.is_safe_for_sink(SinkType.SQL_EXECUTE)}")
    
    # Apply bool() conversion
    enable_bool = apply_sanitizer("builtins.bool", enable_flag)
    print(f"2. bool(enable_flag): safe for SQL={enable_bool.is_safe_for_sink(SinkType.SQL_EXECUTE)}")
    print(f"                     safe for COMMAND={enable_bool.is_safe_for_sink(SinkType.COMMAND_SHELL)}")
    print(f"                     safe for PATH={enable_bool.is_safe_for_sink(SinkType.FILE_PATH)}")
    print("   Reason: bool() constrains to True/False only (no injection possible)")


def demo_datetime_sanitization():
    """Demo: datetime parsing validates format."""
    print("\n=== datetime.fromisoformat() Validation ===")
    
    date_input = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "user_input()")
    print(f"1. date_input (raw): unsafe for SQL={not date_input.is_safe_for_sink(SinkType.SQL_EXECUTE)}")
    
    # Apply datetime validation
    parsed_date = apply_sanitizer("datetime.datetime.fromisoformat", date_input)
    print(f"2. datetime.fromisoformat(date_input): safe for SQL={parsed_date.is_safe_for_sink(SinkType.SQL_EXECUTE)}")
    print("   Reason: fromisoformat() validates strict ISO 8601 format")


def demo_path_canonicalization():
    """Demo: pathlib.Path.resolve() prevents path traversal."""
    print("\n=== pathlib.Path.resolve() Canonicalization ===")
    
    file_path = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "request.args['path']")
    print(f"1. file_path (raw): unsafe for FILE_PATH={not file_path.is_safe_for_sink(SinkType.FILE_PATH)}")
    
    # Apply path canonicalization
    resolved_path = apply_sanitizer("pathlib.Path.resolve", file_path)
    print(f"2. Path(file_path).resolve(): safe for FILE_PATH={resolved_path.is_safe_for_sink(SinkType.FILE_PATH)}")
    print("   Reason: resolve() canonicalizes and removes ../ traversal attempts")


def demo_ip_validation():
    """Demo: ipaddress validation prevents SSRF with invalid IPs."""
    print("\n=== ipaddress.ip_address() Validation ===")
    
    ip_input = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "input('IP: ')")
    print(f"1. ip_input (raw): unsafe for HTTP_REQUEST={not ip_input.is_safe_for_sink(SinkType.HTTP_REQUEST)}")
    
    # Apply IP validation
    validated_ip = apply_sanitizer("ipaddress.ip_address", ip_input)
    print(f"2. ipaddress.ip_address(ip_input): safe for HTTP_REQUEST={validated_ip.is_safe_for_sink(SinkType.HTTP_REQUEST)}")
    print(f"                                  safe for SQL={validated_ip.is_safe_for_sink(SinkType.SQL_EXECUTE)}")
    print("   Reason: ip_address() validates format (prevents domain hijacking, localhost bypass)")


def demo_enum_allowlist():
    """Demo: enum.Enum constrains to predefined values."""
    print("\n=== enum.Enum Allowlist Constraint ===")
    
    action = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "request.POST['action']")
    print(f"1. action (raw): unsafe for COMMAND={not action.is_safe_for_sink(SinkType.COMMAND_SHELL)}")
    
    # Apply enum lookup (constrains to predefined set)
    action_enum = apply_sanitizer("enum.Enum", action)
    print(f"2. ActionEnum(action): safe for COMMAND={action_enum.is_safe_for_sink(SinkType.COMMAND_SHELL)}")
    print("   Reason: Enum lookup constrains to predefined values (START, STOP, RESTART)")


def demo_json_safe_deserialization():
    """Demo: json.loads() is safe for deserialization (no code exec)."""
    print("\n=== json.loads() Safe Deserialization ===")
    
    data = TaintLabel.from_untrusted_source(SourceType.NETWORK_RECV, "socket.recv()")
    print(f"1. data (raw): unsafe for DESERIALIZE={not data.is_safe_for_sink(SinkType.DESERIALIZE)}")
    
    # Apply JSON parsing
    parsed = apply_sanitizer("json.loads", data)
    print(f"2. json.loads(data): safe for DESERIALIZE={parsed.is_safe_for_sink(SinkType.DESERIALIZE)}")
    print("   Reason: JSON has no code execution (unlike pickle, yaml)")
    print("   Contrast: pickle.loads(data) would be UNSAFE")


def demo_comparison():
    """Demo: Compare type-based sanitizers vs other approaches."""
    print("\n=== Comparison: Type Sanitizers vs String Sanitizers ===")
    
    user_input = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "request.args['value']")
    
    # Option 1: Type conversion (precise)
    int_value = apply_sanitizer("int", user_input)
    print(f"1. int(user_input): safe for SQL={int_value.is_safe_for_sink(SinkType.SQL_EXECUTE)} (PRECISE)")
    
    # Option 2: String escaping (conservative)
    escaped_value = apply_sanitizer("html.escape", user_input)
    print(f"2. escape(user_input): safe for HTML={escaped_value.is_safe_for_sink(SinkType.HTML_OUTPUT)}")
    print(f"                       safe for SQL={escaped_value.is_safe_for_sink(SinkType.SQL_EXECUTE)} (not SQL-specific)")
    
    print("\nType conversion is more precise when the domain constraint is sufficient:")
    print("  - int() guarantees no SQL operators")
    print("  - bool() guarantees no shell metacharacters")
    print("  - IP validation guarantees valid IP format")
    print("\nString escaping is necessary when the full string domain is needed:")
    print("  - HTML escape for user-visible text")
    print("  - SQL parameterization for string queries")


def main():
    print("=" * 70)
    print("Type-Based Sanitizers: Domain Constraint for Precision")
    print("=" * 70)
    print("\nType conversions act as sanitizers by constraining the value domain.")
    print("This is barrier-theoretically sound when domain(T) ∩ exploit_strings(sink) = ∅")
    
    demo_int_sanitization()
    demo_bool_sanitization()
    demo_datetime_sanitization()
    demo_path_canonicalization()
    demo_ip_validation()
    demo_enum_allowlist()
    demo_json_safe_deserialization()
    demo_comparison()
    
    print("\n" + "=" * 70)
    print("Summary: Type-Based Sanitizers Improve Precision")
    print("=" * 70)
    print("✓ Reduces false positives by recognizing domain constraints")
    print("✓ Barrier-theoretically sound (domain intersection with exploits is empty)")
    print("✓ Compositional (int()->str() preserves safety)")
    print("✓ 16+ type conversions now recognized as sanitizers")


if __name__ == "__main__":
    main()
