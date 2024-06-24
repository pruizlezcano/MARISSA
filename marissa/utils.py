import os
from typing import List


def remove_files(files: List[str]):
    for file in files:
        if os.path.exists(file):
            os.remove(file)
