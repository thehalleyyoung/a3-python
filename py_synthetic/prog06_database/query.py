"""Query building utilities."""
from typing import Any, List, Optional


class QueryBuilder:
    def __init__(self, table: str):
        self.table = table
        self.conditions = []
        self.columns = ["*"]
        self.order_by = None
        self.limit_value = None
    
    def select(self, *columns):
        self.columns = list(columns) if columns else ["*"]
        return self
    
    def where(self, condition: str):
        self.conditions.append(condition)
        return self
    
    def order(self, column: str, direction: str = "ASC"):
        self.order_by = (column, direction)
        return self
    
    def limit(self, n: int):
        self.limit_value = n
        return self
    
    def build(self) -> str:
        """Build SQL query string."""
        cols = ", ".join(self.columns)
        query = f"SELECT {cols} FROM {self.table}"
        
        if self.conditions:
            where_clause = " AND ".join(self.conditions)
            query += f" WHERE {where_clause}"
        
        if self.order_by:
            query += f" ORDER BY {self.order_by[0]} {self.order_by[1]}"
        
        if self.limit_value:
            query += f" LIMIT {self.limit_value}"
        
        return query
    
    def get_condition(self, index: int) -> str:
        """Get condition at index."""
        # BUG: BOUNDS
        return self.conditions[index]


def execute_query(connection, query: str) -> List[dict]:
    """Execute query and return results."""
    # Simulated - would use actual connection
    return []


def parse_where_clause(clause: str, index: int) -> str:
    """Parse where clause component."""
    parts = clause.split(" AND ")
    # BUG: BOUNDS
    return parts[index]


def format_value(value: Any) -> str:
    """Format value for SQL."""
    if value is None:
        return "NULL"
    if isinstance(value, str):
        return f"'{value}'"
    return str(value)


def get_column_from_result(result: dict, column: str):
    """Get column from result row."""
    # BUG: NULL_PTR
    value = result.get(column)
    return value.strip()


def calculate_query_cost(operations: int, base_cost: float) -> float:
    """Calculate estimated query cost."""
    # BUG: DIV_ZERO if base_cost is 0 (actually multiplication, no bug)
    return operations * base_cost


def normalize_query_time(time: float, baseline: float) -> float:
    """Normalize query time against baseline."""
    # BUG: DIV_ZERO
    return time / baseline
