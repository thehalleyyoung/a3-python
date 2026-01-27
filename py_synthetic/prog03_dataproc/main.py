"""Data processing pipeline - main module."""
from processor import DataProcessor, transform_data
from validators import validate_record, check_schema


def process_batch(records: list, schema: dict) -> list:
    """Process a batch of records."""
    results = []
    for record in records:
        if validate_record(record, schema):
            processed = transform_data(record)
            results.append(processed)
    return results


def get_field(record: dict, field_path: str):
    """Get nested field from record using dot notation."""
    parts = field_path.split(".")
    current = record
    for part in parts:
        # BUG: NULL_PTR - current could become None
        current = current.get(part)
    return current


def aggregate_values(records: list, field: str) -> float:
    """Sum values of a field across records."""
    total = 0
    for record in records:
        # BUG: NULL_PTR - get may return None
        value = record.get(field)
        total += value  # Will fail if value is None
    return total


def get_record_at(records: list, index: int) -> dict:
    """Get record at specific index."""
    # BUG: BOUNDS - no check
    return records[index]


def safe_aggregate(records: list, field: str) -> float:
    """Safe aggregation with None handling."""
    total = 0
    for record in records:
        value = record.get(field, 0)  # Safe: default value
        if value is not None:
            total += value
    return total
