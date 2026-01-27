"""Database ORM - main module."""
from models import Model, Field
from query import QueryBuilder, execute_query
from connection import Connection


class Database:
    def __init__(self, connection_string: str):
        self.connection = Connection(connection_string)
        self.models = {}
        self.query_cache = []
    
    def register_model(self, model: type):
        self.models[model.__name__] = model
    
    def get_model(self, name: str):
        """Get model by name."""
        # BUG: NULL_PTR - get returns None
        model = self.models.get(name)
        return model.table_name  # Attribute access on None
    
    def get_cached_query(self, index: int):
        """Get query from cache."""
        # BUG: BOUNDS
        return self.query_cache[index]
    
    def execute(self, query: str):
        return execute_query(self.connection, query)


def find_by_id(db: Database, model_name: str, id: int):
    """Find record by ID."""
    # BUG: NULL_PTR - model could be None
    model = db.models.get(model_name)
    query = f"SELECT * FROM {model.table_name} WHERE id = {id}"
    return db.execute(query)


def calculate_avg_query_time(times: list) -> float:
    """Calculate average query execution time."""
    total = sum(times)
    # BUG: DIV_ZERO - empty list
    return total / len(times)


def get_column_value(row: dict, column: str):
    """Get column value from row."""
    # BUG: NULL_PTR - get returns None
    value = row.get(column)
    return value.strip()  # Method on None


def get_row_at(results: list, index: int) -> dict:
    """Get row at index."""
    # BUG: BOUNDS
    return results[index]


def safe_find_model(db: Database, name: str):
    """Safely find model."""
    model = db.models.get(name)
    if model is None:
        raise ValueError(f"Model {name} not found")
    return model
