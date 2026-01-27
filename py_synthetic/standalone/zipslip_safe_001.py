"""ZIPSLIP: SAFE - Validates paths before extraction"""

def extract_zip_safe(zip_path, dest):
    """SAFE: Validates extraction paths"""
    import zipfile
    import os
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            member_path = os.path.join(dest, member)
            if not member_path.startswith(os.path.abspath(dest)):
                raise ValueError("Attempted path traversal in zip file")
        zf.extractall(dest)  # SAFE: Paths validated

if __name__ == '__main__':
    import sys
    extract_zip_safe(sys.argv[1], sys.argv[2])
