"""Data validation utilities."""
from typing import Any, Dict, List


def validate_record(record: dict, schema: dict) -> bool:
    """Validate a record against a schema."""
    for field, field_type in schema.items():
        if field not in record:
            return False
        if not isinstance(record[field], field_type):
            return False
    return True


def check_schema(schema: dict) -> bool:
    """Check if schema is well-formed."""
    for field, field_type in schema.items():
        if not isinstance(field, str):
            return False
        if not isinstance(field_type, type):
            return False
    return True


def validate_numeric_range(value: float, min_val: float, max_val: float) -> bool:
    """Check if value is in range."""
    return min_val <= value <= max_val


def validate_string_length(value: str, max_len: int) -> bool:
    """Check if string is within length limit."""
    # BUG: NULL_PTR - value could be None
    return len(value) <= max_len


def get_validation_error(errors: list, index: int) -> str:
    """Get specific validation error."""
    # BUG: BOUNDS - no check
    return errors[index]


def calculate_error_rate(errors: int, total: int) -> float:
    """Calculate error rate as percentage."""
    # BUG: DIV_ZERO - total could be 0
    return (errors / total) * 100


def safe_validate_length(value, max_len: int) -> bool:
    """Safe string length validation."""
    if value is None:
        return True  # Safe: handles None
    return len(str(value)) <= max_len
