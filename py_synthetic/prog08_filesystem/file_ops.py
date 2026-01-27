"""File operations module."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class FileHandler:
    path: str
    mode: str
    content: Optional[bytes] = None
    is_open: bool = False
    
    def open(self):
        self.is_open = True
    
    def close(self):
        self.is_open = False
    
    def read(self) -> bytes:
        return self.content or b""
    
    def write(self, data: bytes):
        self.content = data


def read_file(path: str) -> str:
    """Read file contents."""
    # Simulated
    return ""


def write_file(path: str, content: str) -> bool:
    """Write content to file."""
    # Simulated
    return True


def get_line(content: str, line_num: int) -> str:
    """Get specific line from content."""
    lines = content.split("\n")
    # BUG: BOUNDS
    return lines[line_num]


def get_chunk(content: bytes, start: int, end: int) -> bytes:
    """Get chunk of file content."""
    # BUG: BOUNDS if indices out of range
    return content[start:end]


def calculate_compression_ratio(original: int, compressed: int) -> float:
    """Calculate compression ratio."""
    # BUG: DIV_ZERO
    return original / compressed


def parse_path(path: str, segment: int) -> str:
    """Get path segment."""
    segments = path.split("/")
    # BUG: BOUNDS
    return segments[segment]


def get_file_type(handlers: dict, ext: str):
    """Get file handler for extension."""
    # BUG: NULL_PTR
    handler = handlers.get(ext)
    return handler.name


def split_filename(filename: str) -> tuple:
    """Split filename into name and extension."""
    parts = filename.rsplit(".", 1)
    # BUG: BOUNDS if no extension
    return (parts[0], parts[1])


def safe_get_line(content: str, line_num: int) -> str:
    """Safely get line."""
    lines = content.split("\n")
    if 0 <= line_num < len(lines):
        return lines[line_num]
    return ""
