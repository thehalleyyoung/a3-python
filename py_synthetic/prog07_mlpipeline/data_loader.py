"""Data loading utilities."""
from typing import List, Optional


class DataLoader:
    def __init__(self, path: str):
        self.path = path
        self.data = []
        self.headers = []
    
    def load(self):
        """Load data from file."""
        # Simulated loading
        self.data = []
        self.headers = []
    
    def get_row(self, index: int) -> list:
        """Get row by index."""
        # BUG: BOUNDS
        return self.data[index]
    
    def get_column(self, col_name: str) -> list:
        """Get column by name."""
        # BUG: NULL_PTR if column doesn't exist
        col_idx = self.headers.index(col_name)  # Raises if not found
        return [row[col_idx] for row in self.data]
    
    def get_header(self, index: int) -> str:
        """Get header at index."""
        # BUG: BOUNDS
        return self.headers[index]


def load_csv(path: str, delimiter: str = ",") -> List[list]:
    """Load CSV file."""
    # Simulated - would read actual file
    return []


def split_data(data: list, split_ratio: float) -> tuple:
    """Split data into train/test."""
    split_idx = int(len(data) * split_ratio)
    return data[:split_idx], data[split_idx:]


def get_batch(data: list, batch_idx: int, batch_size: int) -> list:
    """Get batch of data."""
    start = batch_idx * batch_size
    end = start + batch_size
    # BUG: BOUNDS - end could exceed data length
    return [data[i] for i in range(start, end)]


def shuffle_data(data: list, seed: int) -> list:
    """Shuffle data with seed."""
    import random
    random.seed(seed)
    shuffled = data.copy()
    random.shuffle(shuffled)
    return shuffled


def calculate_batch_count(data_size: int, batch_size: int) -> int:
    """Calculate number of batches."""
    # BUG: DIV_ZERO
    return data_size // batch_size


def get_sample(data: list, indices: list) -> list:
    """Get samples at given indices."""
    result = []
    for idx in indices:
        # BUG: BOUNDS
        result.append(data[idx])
    return result


def safe_get_batch(data: list, batch_idx: int, batch_size: int) -> list:
    """Safely get batch."""
    start = batch_idx * batch_size
    end = min(start + batch_size, len(data))
    return data[start:end]
