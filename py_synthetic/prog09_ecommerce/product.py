"""Product module."""
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Product:
    id: str
    name: str
    price: float
    category: str
    stock: int = 0
    description: Optional[str] = None


def get_product_by_id(products: list, product_id: str) -> Optional[Product]:
    """Find product by ID."""
    for product in products:
        if product.id == product_id:
            return product
    return None


def get_product_at(products: list, index: int) -> Product:
    """Get product at index."""
    # BUG: BOUNDS
    return products[index]


def get_product_description(product: Product) -> str:
    """Get product description."""
    # BUG: NULL_PTR - description could be None
    return product.description.upper()


def calculate_stock_value(products: list) -> float:
    """Calculate total stock value."""
    return sum(p.price * p.stock for p in products)


def calculate_avg_price(products: list) -> float:
    """Calculate average product price."""
    total = sum(p.price for p in products)
    # BUG: DIV_ZERO
    return total / len(products)


def search_products(products: list, keyword: str) -> list:
    """Search products by keyword."""
    return [p for p in products if keyword.lower() in p.name.lower()]


def get_category_avg_price(products: list, category: str) -> float:
    """Calculate average price for category."""
    cat_products = [p for p in products if p.category == category]
    total = sum(p.price for p in cat_products)
    # BUG: DIV_ZERO if no products in category
    return total / len(cat_products)


def get_top_n_products(products: list, n: int) -> list:
    """Get top n products by price."""
    sorted_products = sorted(products, key=lambda p: p.price, reverse=True)
    # BUG: BOUNDS if n > len(products)
    return [sorted_products[i] for i in range(n)]


def safe_get_description(product: Product) -> str:
    """Safely get product description."""
    if product.description is None:
        return ""
    return product.description
