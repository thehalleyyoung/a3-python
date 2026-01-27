"""TARSLIP: Unsafe tar extraction"""

def extract_archive(tar_path, dest):
    """BUG: TARSLIP - No path validation on extraction"""
    import tarfile
    with tarfile.open(tar_path) as tar:
        tar.extractall(dest)  # BUG: Can overwrite arbitrary files

if __name__ == '__main__':
    import sys
    extract_archive(sys.argv[1], sys.argv[2])
