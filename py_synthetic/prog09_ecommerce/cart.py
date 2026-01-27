"""Shopping cart module."""
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class CartItem:
    product_id: str
    quantity: int
    price: float


@dataclass
class Cart:
    user_id: str
    items: List[CartItem] = None
    
    def __post_init__(self):
        if self.items is None:
            self.items = []
    
    def get_item(self, index: int) -> CartItem:
        """Get item by index."""
        # BUG: BOUNDS
        return self.items[index]
    
    def find_item(self, product_id: str) -> Optional[CartItem]:
        """Find item by product ID."""
        for item in self.items:
            if item.product_id == product_id:
                return item
        return None
    
    def get_item_price(self, product_id: str) -> float:
        """Get price of item."""
        # BUG: NULL_PTR
        item = self.find_item(product_id)
        return item.price  # Attribute on None


def add_to_cart(cart: Cart, product_id: str, quantity: int, price: float):
    """Add item to cart."""
    item = cart.find_item(product_id)
    if item:
        item.quantity += quantity
    else:
        cart.items.append(CartItem(product_id, quantity, price))


def remove_from_cart(cart: Cart, index: int):
    """Remove item at index."""
    # BUG: BOUNDS
    del cart.items[index]


def calculate_total(cart: Cart) -> float:
    """Calculate cart total."""
    return sum(item.price * item.quantity for item in cart.items)


def calculate_avg_item_price(cart: Cart) -> float:
    """Calculate average item price."""
    total = sum(item.price for item in cart.items)
    # BUG: DIV_ZERO
    return total / len(cart.items)


def get_most_expensive_item(cart: Cart) -> CartItem:
    """Get most expensive item."""
    # BUG: BOUNDS if empty
    return max(cart.items, key=lambda i: i.price)


def apply_coupon(cart: Cart, coupons: dict, code: str) -> float:
    """Apply coupon to cart."""
    # BUG: NULL_PTR
    discount = coupons.get(code)
    return calculate_total(cart) * (1 - discount)  # Operation on None
