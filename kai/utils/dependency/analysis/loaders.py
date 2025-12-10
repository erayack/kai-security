"""
Source loaders for GraphQueryEngine.
"""

import os


class FileSourceLoader:
    """
    Minimal file-backed source loader that can return code spans by line number.
    """

    def __init__(self, target_path: str):
        # Normalize and store the base path where source files live
        self.base_path = os.path.abspath(target_path)

    def _resolve_path(self, file: str) -> str:
        if os.path.isabs(file):
            return file
        return os.path.join(self.base_path, file)

    def read_span(self, file: str, start: int, end: int) -> str:
        """
        Read lines [start, end] (1-indexed, inclusive) from a file.
        """
        if start < 1 or end < start:
            raise ValueError(f"Invalid span: start={start}, end={end}")

        path = self._resolve_path(file)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {file}")
        if not os.path.isfile(path):
            raise IsADirectoryError(f"Not a file: {file}")

        with open(path, "r") as f:
            lines = f.readlines()

        total = len(lines)
        if start > total:
            raise ValueError(f"Start line {start} out of range (file has {total} lines)")

        # Clamp end to file length
        start_idx = start - 1
        end_idx = min(end, total)
        return "".join(lines[start_idx:end_idx])

