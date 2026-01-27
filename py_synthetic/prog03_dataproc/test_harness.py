"""Test harness for data processing - triggers buggy functions."""


def test_get_field_none():
    """Get nested field that doesn't exist - triggers NULL_PTR."""
    record = {"a": {"b": None}}
    # Traverse: record["a"]["b"]["c"] - b is None
    current = record
    current = current.get("a")
    current = current.get("b")  # Returns None
    # BUG: NULL_PTR
    result = current.get("c")  # AttributeError on None
    return result


def test_aggregate_values_none():
    """Aggregate with missing field - triggers NULL_PTR."""
    records = [{"x": 1}, {"y": 2}]  # Second record missing "x"
    field = "x"
    total = 0
    for record in records:
        value = record.get(field)
        # BUG: NULL_PTR - value is None for second record
        total += value
    return total


def test_get_record_at_oob():
    """Get record at bad index - triggers BOUNDS."""
    records = []
    index = 0
    # BUG: BOUNDS
    return records[index]


def test_get_first_n_oob():
    """Get first n records when n > len - triggers BOUNDS."""
    records = [1, 2, 3]
    n = 10
    # BUG: BOUNDS
    return [records[i] for i in range(n)]


def test_divide_into_chunks_zero():
    """Divide into zero-sized chunks - triggers DIV_ZERO."""
    data = [1, 2, 3, 4, 5]
    chunk_size = 0
    # BUG: DIV_ZERO
    num_chunks = len(data) // chunk_size
    return num_chunks


def test_validate_string_length_none():
    """Validate length of None - triggers NULL_PTR."""
    value = None
    max_len = 100
    # BUG: NULL_PTR
    return len(value) <= max_len


def test_get_validation_error_oob():
    """Get validation error at bad index - triggers BOUNDS."""
    errors = []
    index = 0
    # BUG: BOUNDS
    return errors[index]


def test_calculate_error_rate_zero():
    """Calculate error rate with zero total - triggers DIV_ZERO."""
    errors = 0
    total = 0
    # BUG: DIV_ZERO
    return (errors / total) * 100


def test_get_config_value_none():
    """Get config value that's missing - triggers NULL_PTR."""
    config = {}
    key = "missing"
    value = config.get(key)
    # BUG: NULL_PTR
    return value.lower()


# Run tests
if __name__ == "__main__":
    try:
        test_calculate_error_rate_zero()
    except ZeroDivisionError:
        pass
