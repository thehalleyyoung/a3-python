"""ZIPSLIP: Unsafe zip extraction"""

def extract_zip(zip_path, dest):
    """BUG: ZIPSLIP - No path validation on extraction"""
    import zipfile
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)  # BUG: Can overwrite arbitrary files

if __name__ == '__main__':
    import sys
    extract_zip(sys.argv[1], sys.argv[2])
