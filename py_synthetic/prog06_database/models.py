"""Model definitions."""
from dataclasses import dataclass
from typing import Any, List, Optional


@dataclass
class Field:
    name: str
    field_type: type
    nullable: bool = False
    default: Any = None


class Model:
    table_name: str = ""
    fields: List[Field] = []
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def get_field(self, name: str) -> Optional[Field]:
        """Get field by name."""
        for field in self.fields:
            if field.name == name:
                return field
        return None
    
    def get_field_value(self, name: str):
        """Get field value."""
        # BUG: NULL_PTR - getattr may return None
        value = getattr(self, name, None)
        return value.lower()  # Method on potentially None
    
    def get_field_at(self, index: int) -> Field:
        """Get field by index."""
        # BUG: BOUNDS
        return self.fields[index]


class User(Model):
    table_name = "users"
    fields = [
        Field("id", int),
        Field("username", str),
        Field("email", str, nullable=True)
    ]


class Post(Model):
    table_name = "posts"
    fields = [
        Field("id", int),
        Field("title", str),
        Field("content", str),
        Field("author_id", int)
    ]


def get_related_model(model: Model, relation_name: str):
    """Get related model."""
    # BUG: NULL_PTR - relations might not exist
    relations = getattr(model, 'relations', None)
    return relations.get(relation_name)  # Method on None


def calculate_field_ratio(model: Model, type_name: type) -> float:
    """Calculate ratio of fields of given type."""
    matching = sum(1 for f in model.fields if f.field_type == type_name)
    # BUG: DIV_ZERO if no fields
    return matching / len(model.fields)


def get_primary_key(model: Model) -> Field:
    """Get primary key field."""
    # BUG: BOUNDS - assumes at least one field
    return model.fields[0]
