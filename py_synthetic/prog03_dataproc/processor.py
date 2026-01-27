"""Data processing utilities."""
from typing import Any, Dict, List


class DataProcessor:
    def __init__(self, config: dict):
        self.config = config
        self.transforms = []
    
    def add_transform(self, transform):
        self.transforms.append(transform)
    
    def process(self, data: dict) -> dict:
        result = data.copy()
        for transform in self.transforms:
            result = transform(result)
        return result
    
    def get_config_value(self, key: str):
        """Get config value."""
        # BUG: NULL_PTR - may return None then used
        return self.config.get(key)


def transform_data(record: dict) -> dict:
    """Apply standard transformations to a record."""
    result = record.copy()
    # Normalize string fields
    for key, value in result.items():
        if isinstance(value, str):
            result[key] = value.strip().lower()
    return result


def merge_records(records: list) -> dict:
    """Merge multiple records into one."""
    if not records:
        return {}
    
    result = {}
    for record in records:
        result.update(record)
    return result


def split_by_key(records: list, key: str) -> dict:
    """Split records into groups by key value."""
    groups = {}
    for record in records:
        # BUG: NULL_PTR - get returns None if key missing
        key_value = record.get(key)
        # Then using None as dict key (works but may cause issues downstream)
        if key_value not in groups:
            groups[key_value] = []
        groups[key_value].append(record)
    return groups


def get_first_n(records: list, n: int) -> list:
    """Get first n records."""
    # BUG: BOUNDS if n > len(records)
    return [records[i] for i in range(n)]


def divide_into_chunks(data: list, chunk_size: int) -> list:
    """Divide data into chunks."""
    # BUG: DIV_ZERO if chunk_size is 0
    num_chunks = len(data) // chunk_size
    chunks = []
    for i in range(num_chunks):
        start = i * chunk_size
        end = start + chunk_size
        chunks.append(data[start:end])
    return chunks
