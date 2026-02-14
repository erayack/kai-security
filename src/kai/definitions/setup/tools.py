"""Setup agent tools — filesystem and shell operations for repo exploration.

These tools run inside a fresh temp directory. The setup agent uses them
to inspect, clone, build, and classify target repositories.
"""

from kai.workspace.tools import list_dir, read_file, run_shell, search_files

__all__ = ["read_file", "list_dir", "search_files", "run_shell"]
