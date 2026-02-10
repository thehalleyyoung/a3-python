"""
Real-world bug examples that a3-python can automatically detect.

Run: a3 scan examples.py --interprocedural
"""

# Example 1: User Authentication
def authenticate_user(username, user_database):
    """
    Look up user credentials from database.
    BUG: No validation that user exists.
    """
    user_record = user_database.get(username)
    # BUG: user_record could be None if username not found
    return user_record['password_hash']  # NULL_PTR


# Example 2: Percentage Calculation
def calculate_completion_rate(completed, total):
    """
    Calculate completion percentage.
    BUG: No check for zero total.
    """
    if completed > total:
        raise ValueError("Invalid: completed > total")
    # BUG: total could be 0
    return (completed / total) * 100  # DIV_ZERO


# Example 3: Nested Configuration Access
def get_database_host(config):
    """
    Extract database host from config.
    BUG: No None checks on nested attributes.
    """
    # BUG: config or config.database could be None
    return config.database.host  # NULL_PTR


# Example 4: API Response Processing
def get_first_user_email(api_response):
    """
    Get email of first user from API response.
    BUG: Assumes response has users and they have emails.
    """
    users = api_response['users']
    first_user = users[0]  # BOUNDS: users could be empty
    return first_user['email']  # NULL_PTR: first_user could be None


# Example 5: Report Generation
def get_latest_transaction(transactions):
    """
    Get the most recent transaction.
    BUG: No check if transactions list is empty.
    """
    sorted_txns = sorted(transactions, key=lambda t: t.date, reverse=True)
    # BUG: sorted_txns could be empty
    latest = sorted_txns[0]  # BOUNDS
    return latest.amount


# Example 6: Score Averaging
def calculate_average_score(scores):
    """
    Calculate average across all scores.
    BUG: Doesn't handle empty input.
    """
    total = sum(scores.values())
    count = len(scores)
    # BUG: count could be 0
    return total / count  # DIV_ZERO


# Example 7: CSV Parsing
def extract_email_from_csv(csv_line):
    """
    Parse email from third column of CSV.
    BUG: Assumes CSV has at least 3 columns.
    """
    fields = csv_line.split(',')
    # BUG: fields might have < 3 elements
    return fields[2].strip()  # BOUNDS


# Example 8: Investment Return
def calculate_roi(profit, cost):
    """
    Calculate return on investment percentage.
    BUG: No validation of cost.
    """
    # BUG: cost could be 0
    return (profit / cost) * 100  # DIV_ZERO


# Example 9: Product Pricing
def get_product_total_price(inventory, product_id):
    """
    Calculate total price including tax.
    BUG: Doesn't validate product exists.
    """
    product = inventory.lookup(product_id)
    # BUG: product could be None
    price = product.base_price  # NULL_PTR
    tax = product.tax_rate
    return price * (1 + tax)


# Example 10: Cache Retrieval
def get_from_cache(cache, key):
    """
    Retrieve value from cache.
    BUG: Doesn't validate cache entry.
    """
    entry = cache.get(key)
    # BUG: entry could be None
    return entry.data  # NULL_PTR
