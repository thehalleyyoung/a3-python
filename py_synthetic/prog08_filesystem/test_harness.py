"""Test harness for filesystem - triggers buggy functions."""


def test_get_open_file_oob():
    """Get open file at bad index - triggers BOUNDS."""
    open_files = []
    index = 0
    # BUG: BOUNDS
    return open_files[index]


def test_get_cached_none():
    """Get cached content when missing - triggers NULL_PTR."""
    file_cache = {}
    path = "/nonexistent"
    content = file_cache.get(path)
    # BUG: NULL_PTR
    return content.decode()


def test_get_nth_file_oob():
    """Get nth file at bad index - triggers BOUNDS."""
    files = []
    n = 0
    # BUG: BOUNDS
    return files[n]


def test_calculate_avg_file_size_empty():
    """Calculate avg with empty files - triggers DIV_ZERO."""
    class File:
        size = 100
    files = []
    total = sum(f.size for f in files)
    # BUG: DIV_ZERO
    return total / len(files)


def test_get_file_at_path_oob():
    """Get path component at bad depth - triggers BOUNDS."""
    path_parts = ["home", "user"]
    depth = 10
    # BUG: BOUNDS
    return path_parts[depth]


def test_get_line_oob():
    """Get line at bad number - triggers BOUNDS."""
    content = "line1\nline2"
    lines = content.split("\n")
    line_num = 10
    # BUG: BOUNDS
    return lines[line_num]


def test_calculate_compression_ratio_zero():
    """Calculate ratio with zero compressed - triggers DIV_ZERO."""
    original = 1000
    compressed = 0
    # BUG: DIV_ZERO
    return original / compressed


def test_parse_path_oob():
    """Parse path segment at bad index - triggers BOUNDS."""
    path = "/home/user"
    segments = path.split("/")
    segment = 10
    # BUG: BOUNDS
    return segments[segment]


def test_get_file_type_none():
    """Get file type when extension unknown - triggers NULL_PTR."""
    handlers = {}
    ext = ".unknown"
    handler = handlers.get(ext)
    # BUG: NULL_PTR
    return handler.name


def test_split_filename_no_ext():
    """Split filename without extension - triggers BOUNDS."""
    filename = "noextension"
    parts = filename.rsplit(".", 1)
    # BUG: BOUNDS - only 1 part
    return (parts[0], parts[1])


def test_get_entry_oob():
    """Get entry at bad index - triggers BOUNDS."""
    entries = []
    index = 0
    # BUG: BOUNDS
    return entries[index]


def test_get_entry_size_none():
    """Get size of nonexistent entry - triggers NULL_PTR."""
    entries = []
    name = "missing"
    entry = None
    for e in entries:
        if e == name:
            entry = e
    # BUG: NULL_PTR
    return entry.size


def test_get_subdirectory_oob():
    """Get subdirectory at bad index - triggers BOUNDS."""
    entries = []
    index = 0
    # BUG: BOUNDS
    return entries[index]


def test_calculate_dir_usage_zero():
    """Calculate usage with zero total - triggers DIV_ZERO."""
    used = 100
    total = 0
    # BUG: DIV_ZERO
    return (used / total) * 100


def test_get_largest_file_empty():
    """Get largest from empty - triggers BOUNDS."""
    entries = []
    # BUG: BOUNDS (max of empty sequence)
    return max(entries, key=lambda e: e.get('size', 0))


def test_get_owner_none():
    """Get owner when file not found - triggers NULL_PTR."""
    file_map = {}
    path = "/nonexistent"
    perms = file_map.get(path)
    # BUG: NULL_PTR
    return perms.owner


def test_get_permission_at_oob():
    """Get permission at bad index - triggers BOUNDS."""
    perm_list = []
    index = 0
    # BUG: BOUNDS
    return perm_list[index]


def test_parse_permission_string_oob():
    """Parse permission at bad position - triggers BOUNDS."""
    perm_str = "rwx"
    pos = 10
    # BUG: BOUNDS
    return perm_str[pos]


def test_calculate_permission_ratio_zero():
    """Calculate ratio with zero total - triggers DIV_ZERO."""
    allowed = 5
    total = 0
    # BUG: DIV_ZERO
    return allowed / total


def test_get_group_members_none():
    """Get members of nonexistent group - triggers NULL_PTR."""
    groups = {}
    group_name = "nonexistent"
    members = groups.get(group_name)
    # BUG: NULL_PTR
    return members.copy()


# Run tests
if __name__ == "__main__":
    try:
        test_calculate_compression_ratio_zero()
    except ZeroDivisionError:
        pass
