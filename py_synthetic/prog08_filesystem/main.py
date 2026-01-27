"""File System Manager - main module."""
from file_ops import FileHandler, read_file, write_file
from directory import Directory, list_directory
from permissions import check_permission, get_owner


class FileSystemManager:
    def __init__(self, root_path: str):
        self.root = root_path
        self.open_files = []
        self.file_cache = {}
    
    def get_open_file(self, index: int) -> FileHandler:
        """Get open file by index."""
        # BUG: BOUNDS
        return self.open_files[index]
    
    def get_cached(self, path: str):
        """Get cached file content."""
        # BUG: NULL_PTR
        content = self.file_cache.get(path)
        return content.decode()  # Method on None
    
    def close_all(self):
        for f in self.open_files:
            f.close()
        self.open_files.clear()


def find_file(files: list, name: str):
    """Find file by name."""
    for f in files:
        if f.name == name:
            return f
    return None


def get_file_extension(filename: str) -> str:
    """Get file extension."""
    parts = filename.split(".")
    # BUG: BOUNDS - assumes extension exists
    return parts[-1]


def calculate_dir_size(files: list) -> int:
    """Calculate total directory size."""
    return sum(f.size for f in files)


def get_nth_file(files: list, n: int):
    """Get nth file from list."""
    # BUG: BOUNDS
    return files[n]


def calculate_avg_file_size(files: list) -> float:
    """Calculate average file size."""
    total = sum(f.size for f in files)
    # BUG: DIV_ZERO
    return total / len(files)


def get_file_at_path(path_parts: list, depth: int) -> str:
    """Get path component at depth."""
    # BUG: BOUNDS
    return path_parts[depth]
