"""Test harness for e-commerce - triggers buggy functions."""


def test_get_product_oob():
    """Get product at bad index - triggers BOUNDS."""
    products = []
    index = 0
    # BUG: BOUNDS
    return products[index]


def test_get_cart_none():
    """Get cart when user doesn't exist - triggers NULL_PTR."""
    carts = {}
    user_id = "nonexistent"
    cart = carts.get(user_id)
    # BUG: NULL_PTR
    return cart.items


def test_get_order_oob():
    """Get order at bad index - triggers BOUNDS."""
    orders = []
    index = 0
    # BUG: BOUNDS
    return orders[index]


def test_calculate_avg_order_value_empty():
    """Calculate avg with empty orders - triggers DIV_ZERO."""
    class Order:
        total = 100.0
    orders = []
    total = sum(o.total for o in orders)
    # BUG: DIV_ZERO
    return total / len(orders)


def test_get_cheapest_product_empty():
    """Get cheapest from empty list - triggers BOUNDS."""
    products = []
    # BUG: BOUNDS (min of empty sequence)
    return min(products, key=lambda p: p.get('price', 0))


def test_calculate_discount_ratio_zero():
    """Calculate ratio with zero original - triggers DIV_ZERO."""
    original = 0.0
    discounted = 0.0
    # BUG: DIV_ZERO
    return (original - discounted) / original


def test_get_item_oob():
    """Get cart item at bad index - triggers BOUNDS."""
    items = []
    index = 0
    # BUG: BOUNDS
    return items[index]


def test_get_item_price_none():
    """Get price of nonexistent item - triggers NULL_PTR."""
    items = []
    product_id = "nonexistent"
    item = None
    for i in items:
        if i.get('product_id') == product_id:
            item = i
    # BUG: NULL_PTR
    return item.price


def test_remove_from_cart_oob():
    """Remove from empty cart - triggers BOUNDS."""
    items = []
    index = 0
    # BUG: BOUNDS
    del items[index]


def test_calculate_avg_item_price_empty():
    """Calculate avg with empty cart - triggers DIV_ZERO."""
    items = []
    total = sum(item.get('price', 0) for item in items)
    # BUG: DIV_ZERO
    return total / len(items)


def test_get_most_expensive_item_empty():
    """Get most expensive from empty - triggers BOUNDS."""
    items = []
    # BUG: BOUNDS (max of empty sequence)
    return max(items, key=lambda i: i.get('price', 0))


def test_apply_coupon_none():
    """Apply nonexistent coupon - triggers NULL_PTR."""
    coupons = {}
    code = "INVALID"
    cart_total = 100.0
    discount = coupons.get(code)
    # BUG: NULL_PTR (None * float)
    return cart_total * (1 - discount)


def test_get_product_at_oob():
    """Get product at bad index - triggers BOUNDS."""
    products = []
    index = 0
    # BUG: BOUNDS
    return products[index]


def test_get_product_description_none():
    """Get description when None - triggers NULL_PTR."""
    class Product:
        description = None
    product = Product()
    # BUG: NULL_PTR
    return product.description.upper()


def test_calculate_avg_price_empty():
    """Calculate avg with empty products - triggers DIV_ZERO."""
    products = []
    total = sum(p.get('price', 0) for p in products)
    # BUG: DIV_ZERO
    return total / len(products)


def test_get_category_avg_price_empty():
    """Calculate avg for empty category - triggers DIV_ZERO."""
    products = [{"category": "electronics", "price": 100}]
    category = "clothing"  # No products in this category
    cat_products = [p for p in products if p.get("category") == category]
    total = sum(p.get('price', 0) for p in cat_products)
    # BUG: DIV_ZERO
    return total / len(cat_products)


def test_get_top_n_products_oob():
    """Get top n when n > len - triggers BOUNDS."""
    products = [{"price": 100}, {"price": 200}]
    n = 10
    sorted_products = sorted(products, key=lambda p: p.get("price", 0), reverse=True)
    # BUG: BOUNDS
    return [sorted_products[i] for i in range(n)]


def test_get_order_item_oob():
    """Get order item at bad index - triggers BOUNDS."""
    items = []
    index = 0
    # BUG: BOUNDS
    return items[index]


def test_get_shipping_address_none():
    """Get shipping when None - triggers NULL_PTR."""
    class Order:
        shipping_address = None
    order = Order()
    # BUG: NULL_PTR
    return order.shipping_address.upper()


def test_calculate_avg_order_item_price_empty():
    """Calculate avg with empty order - triggers DIV_ZERO."""
    items = []
    total = sum(item.get('price', 0) for item in items)
    # BUG: DIV_ZERO
    return total / len(items)


def test_get_order_at_oob():
    """Get order at bad index - triggers BOUNDS."""
    orders = []
    index = 0
    # BUG: BOUNDS
    return orders[index]


def test_split_order_zero():
    """Split order with zero count - triggers DIV_ZERO."""
    items = [1, 2, 3]
    split_count = 0
    # BUG: DIV_ZERO
    items_per_split = len(items) // split_count


# Run tests
if __name__ == "__main__":
    try:
        test_calculate_avg_order_value_empty()
    except ZeroDivisionError:
        pass
