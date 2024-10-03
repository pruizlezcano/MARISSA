import os
from typing import List


def remove_files(files: List[str]):
    """Remove files from the filesystem.

    Args:
        files (List[str]): List of files to remove.
    """
    for file in files:
        if os.path.exists(file):
            os.remove(file)
