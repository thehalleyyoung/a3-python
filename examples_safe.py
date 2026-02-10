"""
Safe versions with proper validation.

Run: a3 scan examples_safe.py --interprocedural
"""

# Example 1: User Authentication (SAFE)
def authenticate_user(username, user_database):
    """
    Look up user credentials with validation.
    SAFE: Checks if user exists.
    """
    user_record = user_database.get(username)
    if user_record is not None:
        return user_record['password_hash']
    return None


# Example 2: Percentage Calculation (SAFE)
def calculate_completion_rate(completed, total):
    """
    Calculate completion percentage safely.
    SAFE: Checks for zero before division.
    """
    if completed > total:
        raise ValueError("Invalid: completed > total")
    if total != 0:
        return (completed / total) * 100
    return 0.0


# Example 3: Nested Configuration Access (SAFE)
def get_database_host(config):
    """
    Extract database host with validation.
    SAFE: Checks nested attributes.
    """
    if config is not None and config.database is not None:
        return config.database.host
    return "localhost"


# Example 4: API Response Processing (SAFE)
def get_first_user_email(api_response):
    """
    Get first user email with validation.
    SAFE: Checks array bounds and None values.
    """
    users = api_response.get('users', [])
    if len(users) > 0:
        first_user = users[0]
        if first_user is not None:
            return first_user.get('email')
    return None


# Example 5: Report Generation (SAFE)
def get_latest_transaction(transactions):
    """
    Get most recent transaction safely.
    SAFE: Checks if list is empty.
    """
    sorted_txns = sorted(transactions, key=lambda t: t.date, reverse=True)
    if len(sorted_txns) > 0:
        return sorted_txns[0].amount
    return 0.0


# Example 6: Score Averaging (SAFE)
def calculate_average_score(scores):
    """
    Calculate average with empty check.
    SAFE: Validates count before division.
    """
    total = sum(scores.values())
    count = len(scores)
    if count > 0:
        return total / count
    return 0.0


# Example 7: CSV Parsing (SAFE)
def extract_email_from_csv(csv_line):
    """
    Parse email with column validation.
    SAFE: Checks field count.
    """
    fields = csv_line.split(',')
    if len(fields) >= 3:
        return fields[2].strip()
    return None


# Example 8: Investment Return (SAFE)
def calculate_roi(profit, cost):
    """
    Calculate ROI with validation.
    SAFE: Checks for zero cost.
    """
    if cost != 0:
        return (profit / cost) * 100
    return 0.0


# Example 9: Product Pricing (SAFE)
def get_product_total_price(inventory, product_id):
    """
    Calculate price with validation.
    SAFE: Checks product exists.
    """
    product = inventory.lookup(product_id)
    if product is not None:
        price = product.base_price
        tax = product.tax_rate
        return price * (1 + tax)
    return 0.0


# Example 10: Cache Retrieval (SAFE)
def get_from_cache(cache, key):
    """
    Retrieve from cache safely.
    SAFE: Validates entry exists.
    """
    entry = cache.get(key)
    if entry is not None:
        return entry.data
    return None
