"""
Source loaders for GraphQueryEngine.
"""

import os


class FileSourceLoader:
    """
    Minimal file-backed source loader that can return code spans by line number.

    Handles path remapping for dependency graphs built on different machines
    by trying multiple resolution strategies.
    """

    def __init__(self, target_path: str):
        # Normalize and store the base path where source files live
        self.base_path = os.path.abspath(target_path)

    def _resolve_path(self, file: str) -> str:
        """
        Resolve a file path, handling cross-machine path remapping.

        Tries:
        1. Direct path (if exists)
        2. Join with base_path (if relative)
        3. Extract relative part from known patterns (contracts/, src/)
        4. Extract filename and search in base_path tree
        """
        # 1. If absolute and exists, use directly
        if os.path.isabs(file) and os.path.exists(file):
            return file

        # 2. If relative, try joining with base_path
        if not os.path.isabs(file):
            joined = os.path.join(self.base_path, file)
            if os.path.exists(joined):
                return joined

        # 3. Try to extract relative path from known markers
        # Common patterns across frameworks (with or without leading /)
        # TODO: Move to DomainAdapter.get_source_markers() for proper framework support
        markers = [
            "contracts/",
            "src/",
            "lib/",
            "test/",  # Solidity (Foundry/Hardhat)
            "programs/",
            "tests/",
            "crates/",  # Rust/Anchor
        ]
        for marker in markers:
            # Check both with and without leading slash
            for check_marker in [f"/{marker}", marker]:
                if check_marker in file:
                    # Extract from the marker onwards (excluding the marker itself)
                    rel_part = file.split(check_marker, 1)[1]
                    # Try just the relative part
                    candidate = os.path.join(self.base_path, rel_part)
                    if os.path.exists(candidate):
                        return candidate
                    # Try with marker included
                    candidate_with_marker = os.path.join(
                        self.base_path, marker, rel_part
                    )
                    if os.path.exists(candidate_with_marker):
                        return candidate_with_marker
                    # For double-nested patterns like contracts/contracts/, try stripping one level
                    if rel_part.startswith(marker):
                        inner_part = rel_part[len(marker) :]
                        inner_candidate = os.path.join(
                            self.base_path, marker, inner_part
                        )
                        if os.path.exists(inner_candidate):
                            return inner_candidate

        # 4. Last resort: just the filename in base_path (for flat structures)
        basename = os.path.basename(file)
        flat_candidate = os.path.join(self.base_path, basename)
        if os.path.exists(flat_candidate):
            return flat_candidate

        # If nothing worked, return the joined path (will fail with FileNotFoundError later)
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
            raise ValueError(
                f"Start line {start} out of range (file has {total} lines)"
            )

        # Clamp end to file length
        start_idx = start - 1
        end_idx = min(end, total)
        return "".join(lines[start_idx:end_idx])
