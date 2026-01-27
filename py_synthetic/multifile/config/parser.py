"""Config - parser with None bug."""

def parse_config(text):
    return None  # Simulating parse failure

def get_value(config):
    return config.get("key")  # BUG: config could be None

# Trigger
config = None
result = get_value(config)
