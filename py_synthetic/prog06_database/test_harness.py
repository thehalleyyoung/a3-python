"""Test harness for database - triggers buggy functions."""


def test_get_model_none():
    """Get model that doesn't exist - triggers NULL_PTR."""
    models = {}
    name = "NonExistent"
    model = models.get(name)
    # BUG: NULL_PTR
    return model.table_name


def test_get_cached_query_oob():
    """Get cached query at bad index - triggers BOUNDS."""
    query_cache = []
    index = 0
    # BUG: BOUNDS
    return query_cache[index]


def test_find_by_id_none():
    """Find by ID when model missing - triggers NULL_PTR."""
    models = {}
    model_name = "User"
    model = models.get(model_name)
    # BUG: NULL_PTR
    query = f"SELECT * FROM {model.table_name}"


def test_calculate_avg_query_time_empty():
    """Calculate avg with empty times - triggers DIV_ZERO."""
    times = []
    total = sum(times)
    # BUG: DIV_ZERO
    return total / len(times)


def test_get_column_value_none():
    """Get column that doesn't exist - triggers NULL_PTR."""
    row = {}
    column = "name"
    value = row.get(column)
    # BUG: NULL_PTR
    return value.strip()


def test_get_row_at_oob():
    """Get row at bad index - triggers BOUNDS."""
    results = []
    index = 0
    # BUG: BOUNDS
    return results[index]


def test_get_field_value_none():
    """Get field value when missing - triggers NULL_PTR."""
    class Model:
        pass
    model = Model()
    name = "missing_field"
    value = getattr(model, name, None)
    # BUG: NULL_PTR
    return value.lower()


def test_get_field_at_oob():
    """Get field at bad index - triggers BOUNDS."""
    fields = []
    index = 0
    # BUG: BOUNDS
    return fields[index]


def test_get_related_model_none():
    """Get related model when none - triggers NULL_PTR."""
    class Model:
        relations = None
    model = Model()
    relations = getattr(model, 'relations', None)
    # BUG: NULL_PTR
    return relations.get("posts")


def test_calculate_field_ratio_empty():
    """Calculate ratio with empty fields - triggers DIV_ZERO."""
    fields = []
    matching = sum(1 for f in fields if True)
    # BUG: DIV_ZERO
    return matching / len(fields)


def test_get_primary_key_empty():
    """Get primary key from empty fields - triggers BOUNDS."""
    fields = []
    # BUG: BOUNDS
    return fields[0]


def test_get_condition_oob():
    """Get condition at bad index - triggers BOUNDS."""
    conditions = []
    index = 0
    # BUG: BOUNDS
    return conditions[index]


def test_parse_where_clause_oob():
    """Parse where clause at bad index - triggers BOUNDS."""
    clause = "id = 1"  # Only one condition
    parts = clause.split(" AND ")
    index = 5
    # BUG: BOUNDS
    return parts[index]


def test_get_column_from_result_none():
    """Get column when missing - triggers NULL_PTR."""
    result = {}
    column = "id"
    value = result.get(column)
    # BUG: NULL_PTR
    return value.strip()


def test_normalize_query_time_zero():
    """Normalize with zero baseline - triggers DIV_ZERO."""
    time = 1.0
    baseline = 0.0
    # BUG: DIV_ZERO
    return time / baseline


def test_connection_get_oob():
    """Get connection at bad index - triggers BOUNDS."""
    active_connections = []
    index = 0
    # BUG: BOUNDS
    return active_connections[index]


def test_pool_get_empty():
    """Get from empty pool - triggers BOUNDS."""
    available = []
    # BUG: BOUNDS
    return available.pop(0)


def test_pool_get_at_oob():
    """Get connection at bad index - triggers BOUNDS."""
    connections = []
    index = 0
    # BUG: BOUNDS
    return connections[index]


def test_parse_connection_string_no_equals():
    """Parse connection without equals - triggers BOUNDS."""
    conn_str = "host;port"  # No =value
    parts = conn_str.split(";")
    for part in parts:
        key_val = part.split("=")
        # BUG: BOUNDS
        result = {key_val[0]: key_val[1]}


def test_get_connection_param_none():
    """Get param when missing - triggers NULL_PTR."""
    params = {}
    key = "host"
    value = params.get(key)
    # BUG: NULL_PTR
    return value.strip()


def test_calculate_pool_utilization_zero():
    """Calculate utilization with zero total - triggers DIV_ZERO."""
    active = 5
    total = 0
    # BUG: DIV_ZERO
    return active / total


# Run tests
if __name__ == "__main__":
    try:
        test_calculate_avg_query_time_empty()
    except ZeroDivisionError:
        pass
