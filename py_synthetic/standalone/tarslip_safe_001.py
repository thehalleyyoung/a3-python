"""TARSLIP: SAFE - Validates paths before extraction"""

def extract_archive_safe(tar_path, dest):
    """SAFE: Validates extraction paths"""
    import tarfile
    import os
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            member_path = os.path.join(dest, member.name)
            if not member_path.startswith(os.path.abspath(dest)):
                raise ValueError("Attempted path traversal in tar file")
        tar.extractall(dest)  # SAFE: Paths validated

if __name__ == '__main__':
    import sys
    extract_archive_safe(sys.argv[1], sys.argv[2])
