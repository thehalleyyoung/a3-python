"""Config - validator with None bug."""

def validate_field(field):
    return field.strip()  # BUG: field could be None

def validate_all(fields):
    for f in fields:
        validate_field(f)

# Trigger
result = validate_field(None)
