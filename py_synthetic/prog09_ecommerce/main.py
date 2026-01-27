"""E-commerce system - main module."""
from cart import Cart, add_to_cart, calculate_total
from product import Product, get_product_by_id
from order import Order, create_order


class ECommerceApp:
    def __init__(self):
        self.products = []
        self.carts = {}
        self.orders = []
    
    def get_product(self, index: int) -> Product:
        """Get product by index."""
        # BUG: BOUNDS
        return self.products[index]
    
    def get_cart(self, user_id: str) -> Cart:
        """Get user's cart."""
        # BUG: NULL_PTR
        cart = self.carts.get(user_id)
        return cart.items  # Attribute on None
    
    def get_order(self, index: int) -> Order:
        """Get order by index."""
        # BUG: BOUNDS
        return self.orders[index]
    
    def calculate_avg_order_value(self) -> float:
        """Calculate average order value."""
        total = sum(o.total for o in self.orders)
        # BUG: DIV_ZERO
        return total / len(self.orders)


def apply_discount(price: float, discount_percent: float) -> float:
    """Apply percentage discount."""
    return price * (1 - discount_percent / 100)


def calculate_tax(subtotal: float, tax_rate: float) -> float:
    """Calculate tax amount."""
    return subtotal * tax_rate


def get_category_products(products: list, category: str) -> list:
    """Filter products by category."""
    return [p for p in products if p.category == category]


def get_cheapest_product(products: list) -> Product:
    """Get cheapest product."""
    # BUG: BOUNDS if empty (min of empty sequence)
    return min(products, key=lambda p: p.price)


def calculate_discount_ratio(original: float, discounted: float) -> float:
    """Calculate how much discount was applied."""
    # BUG: DIV_ZERO
    return (original - discounted) / original
