"""Order module."""
from dataclasses import dataclass
from typing import List, Optional
from cart import Cart, CartItem


@dataclass
class OrderItem:
    product_id: str
    quantity: int
    price: float


@dataclass
class Order:
    id: str
    user_id: str
    items: List[OrderItem]
    total: float
    status: str = "pending"
    shipping_address: Optional[str] = None


def create_order(order_id: str, cart: Cart, user_id: str) -> Order:
    """Create order from cart."""
    items = [OrderItem(i.product_id, i.quantity, i.price) for i in cart.items]
    total = sum(i.price * i.quantity for i in items)
    return Order(id=order_id, user_id=user_id, items=items, total=total)


def get_order_item(order: Order, index: int) -> OrderItem:
    """Get order item at index."""
    # BUG: BOUNDS
    return order.items[index]


def get_shipping_address(order: Order) -> str:
    """Get shipping address."""
    # BUG: NULL_PTR - address could be None
    return order.shipping_address.upper()


def calculate_avg_order_item_price(order: Order) -> float:
    """Calculate average item price in order."""
    total = sum(item.price for item in order.items)
    # BUG: DIV_ZERO
    return total / len(order.items)


def get_orders_by_status(orders: list, status: str) -> list:
    """Filter orders by status."""
    return [o for o in orders if o.status == status]


def get_order_at(orders: list, index: int) -> Order:
    """Get order at index."""
    # BUG: BOUNDS
    return orders[index]


def calculate_order_tax(order: Order, tax_rate: float) -> float:
    """Calculate tax for order."""
    return order.total * tax_rate


def split_order(order: Order, split_count: int) -> list:
    """Split order into parts."""
    # BUG: DIV_ZERO
    items_per_split = len(order.items) // split_count
    return [order.items[i:i+items_per_split] for i in range(0, len(order.items), items_per_split)]


def safe_get_shipping(order: Order) -> str:
    """Safely get shipping address."""
    if order.shipping_address is None:
        return "No address"
    return order.shipping_address
