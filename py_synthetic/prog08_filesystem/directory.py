"""Directory operations module."""
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class FileInfo:
    name: str
    size: int
    is_dir: bool


@dataclass
class Directory:
    path: str
    entries: List[FileInfo] = None
    parent: Optional['Directory'] = None
    
    def __post_init__(self):
        if self.entries is None:
            self.entries = []
    
    def get_entry(self, index: int) -> FileInfo:
        """Get entry by index."""
        # BUG: BOUNDS
        return self.entries[index]
    
    def find_entry(self, name: str) -> Optional[FileInfo]:
        """Find entry by name."""
        for entry in self.entries:
            if entry.name == name:
                return entry
        return None
    
    def get_entry_size(self, name: str) -> int:
        """Get size of entry by name."""
        # BUG: NULL_PTR
        entry = self.find_entry(name)
        return entry.size  # Attribute on None


def list_directory(path: str) -> List[FileInfo]:
    """List directory contents."""
    # Simulated
    return []


def get_subdirectory(entries: list, index: int) -> Directory:
    """Get subdirectory at index."""
    # BUG: BOUNDS
    return entries[index]


def calculate_dir_usage(used: int, total: int) -> float:
    """Calculate directory usage percentage."""
    # BUG: DIV_ZERO
    return (used / total) * 100


def get_parent_path(path: str) -> str:
    """Get parent directory path."""
    parts = path.rsplit("/", 1)
    # BUG: BOUNDS if root path
    return parts[0] if parts[0] else "/"


def count_files_by_ext(entries: list, ext: str) -> int:
    """Count files with extension."""
    return sum(1 for e in entries if e.name.endswith(ext))


def get_largest_file(entries: list) -> FileInfo:
    """Get largest file in directory."""
    # BUG: BOUNDS if empty
    return max(entries, key=lambda e: e.size)


def safe_get_entry(directory: Directory, name: str) -> Optional[FileInfo]:
    """Safely get entry."""
    return directory.find_entry(name)
