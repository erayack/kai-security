"""
File I/O tools for agents.

This module contains tools for reading, listing, creating, and updating files
with proper path normalization and scope validation.
"""

import os
import uuid
from typing import Optional, Union

from kai.agents.utils import load_gitignore_spec, should_ignore_path

from .shared import get_current_agent, normalize_agent_path


def read_file(
    file_path: str, start_line: Optional[int] = None, end_line: Optional[int] = None
) -> str:
    """
    Read a file with a given path, optionally specifying a line range.

    Args:
        file_path: The path to the file.
        start_line: Optional starting line number (1-indexed, inclusive).
        end_line: Optional ending line number (1-indexed, inclusive).

    Returns:
        The content of the file (or specified line range), or an error message if the file cannot be read.

    Examples:
        read_file("foo.rs")              # Full file
        read_file("foo.rs", 100, 150)    # Lines 100-150 only
    """
    try:
        # Resolve relative paths relative to agent's working_dir
        try:
            normalized = normalize_agent_path(file_path)
            if normalized is None:
                return f"Error: Invalid path resolution for {file_path}"
            file_path = normalized
        except (NameError, TypeError):
            pass

        # Now convert to absolute path for scope validation
        abs_path = os.path.abspath(file_path)

        # Scope validation (if get_current_agent is available)
        try:
            agent = get_current_agent()
            if agent and hasattr(agent, "restricted_scope") and agent.restricted_scope:
                if not any(
                    abs_path.startswith(allowed) for allowed in agent.allowed_paths
                ):
                    return f"Error: Access denied. File '{file_path}' is outside assigned scope."
        except (NameError, TypeError):
            # get_current_agent not defined or returns None, skip scope validation
            pass

        # Ensure the file path is properly resolved
        if not os.path.exists(abs_path):
            return f"Error: File {file_path} does not exist"

        if not os.path.isfile(abs_path):
            return f"Error: {file_path} is not a file"

        with open(abs_path, "r") as f:
            if start_line is None and end_line is None:
                # Read entire file
                return f.read()
            else:
                # Read specific line range
                lines = f.readlines()
                total_lines = len(lines)

                # Empty files should just return empty content, regardless of range.
                if total_lines == 0:
                    return ""

                # Validate line numbers
                if start_line is not None and (
                    start_line < 1 or start_line > total_lines
                ):
                    return f"Error: start_line {start_line} is out of range (file has {total_lines} lines)"

                # If end_line is past EOF, clamp it to the file length instead of erroring.
                if end_line is not None:
                    if end_line < 1:
                        return f"Error: end_line {end_line} is out of range (file has {total_lines} lines)"
                    if end_line > total_lines:
                        end_line = total_lines

                if (
                    start_line is not None
                    and end_line is not None
                    and start_line > end_line
                ):
                    return f"Error: start_line {start_line} cannot be greater than end_line {end_line}"

                # Extract line range (convert to 0-indexed)
                start_idx = (start_line - 1) if start_line else 0
                end_idx = end_line if end_line else total_lines

                return "".join(lines[start_idx:end_idx])

    except PermissionError:
        return f"Error: Permission denied accessing {file_path}"
    except Exception as e:
        return f"Error: {e}"


def list_files(path: Optional[str] = None, depth: int = 2) -> str:
    """
    Display all files and directories as a tree structure.

    Example output:
    ```
    ./
    ├── user.md
    └── entities/
        ├── 452_willow_creek_dr.md
        └── frank_miller_plumbing.md
    ```

    Args:
        path: Optional path to the directory to display. If None, uses current working directory.
        depth: Maximum depth to traverse. Default is 2.
           depth=0 shows only the root directory contents,
           depth=1 shows root and one level of subdirectories, etc.
               Set to a large number (e.g., 10) for deep exploration.

    Returns:
        A string representation of the directory tree.

    Examples:
        # List current directory with default depth of 2
        tree = list_files()

        # List specific directory with custom depth
        tree = list_files(path="bft", depth=1)

        # Deep exploration
        tree = list_files(depth=10)
    """
    try:
        # Use agent's working_dir if available and no path specified, otherwise os.getcwd()
        if path is None:
            try:
                agent = get_current_agent()
                dir_path = agent.working_dir if agent else os.getcwd()
            except (NameError, TypeError):
                dir_path = os.getcwd()
        else:
            normalized = normalize_agent_path(path)
            if normalized is None:
                return f"Error: Invalid path resolution for {path}"
            dir_path = normalized

        # Scope validation (if get_current_agent is available)
        try:
            agent = get_current_agent()
            if agent and hasattr(agent, "restricted_scope") and agent.restricted_scope:
                abs_path = os.path.abspath(dir_path)
                if not any(
                    abs_path.startswith(allowed) for allowed in agent.allowed_paths
                ):
                    return f"Error: Access denied. Directory '{dir_path}' is outside assigned scope."
        except (NameError, TypeError):
            # get_current_agent not defined or returns None, skip scope validation
            pass

        # Load gitignore patterns
        gitignore_spec = load_gitignore_spec(dir_path)

        def build_tree(start_path, prefix="", is_last=True, current_depth=0):
            """Recursively build tree structure"""
            entries = []
            try:
                items = sorted(os.listdir(start_path))
                # Filter out hidden files, __pycache__, and gitignored items
                filtered_items = []
                for item in items:
                    if item.startswith(".") or item == "__pycache__":
                        continue
                    item_path = os.path.join(start_path, item)
                    if should_ignore_path(item_path, dir_path, gitignore_spec):
                        continue
                    filtered_items.append(item)
                items = filtered_items
            except PermissionError:
                return f"{prefix}[Permission Denied]\n"

            if not items:
                return ""

            for i, item in enumerate(items):
                item_path = os.path.join(start_path, item)
                is_last_item = i == len(items) - 1

                # Choose the right prefix characters
                if is_last_item:
                    current_prefix = prefix + "└── "
                    extension = prefix + "    "
                else:
                    current_prefix = prefix + "├── "
                    extension = prefix + "│   "

                if os.path.isdir(item_path):
                    # Check if we've reached the depth limit
                    if depth is not None and current_depth >= depth:
                        entries.append(f"{current_prefix}{item}/ [...]\n")
                    else:
                        # Check if directory is empty (considering gitignore)
                        try:
                            dir_contents = []
                            for f in os.listdir(item_path):
                                if f.startswith(".") or f == "__pycache__":
                                    continue
                                f_path = os.path.join(item_path, f)
                                if should_ignore_path(f_path, dir_path, gitignore_spec):
                                    continue
                                dir_contents.append(f)

                            if not dir_contents:
                                entries.append(f"{current_prefix}{item}/ (empty)\n")
                            else:
                                entries.append(f"{current_prefix}{item}/\n")
                                # Recursively add subdirectory contents
                                entries.append(
                                    build_tree(
                                        item_path,
                                        extension,
                                        is_last_item,
                                        current_depth + 1,
                                    )
                                )
                        except PermissionError:
                            entries.append(
                                f"{current_prefix}{item}/ [Permission Denied]\n"
                            )
                else:
                    entries.append(f"{current_prefix}{item}\n")

            return "".join(entries)

        # Start with the root directory
        tree = f"./\n{build_tree(dir_path)}"
        return tree.rstrip()  # Remove trailing newline

    except Exception as e:
        return f"Error: {e}"


def update_file(file_path: str, old_content: str, new_content: str) -> Union[bool, str]:
    """
    Simple find-and-replace update method for files.

    This is an easier alternative to write_to_file() that doesn't require
    creating git-style diffs. It performs a simple string replacement.

    Parameters
    ----------
    file_path : str
        Path to the file to update.
    old_content : str
        The exact text to find and replace in the file.
    new_content : str
        The text to replace old_content with.

    Returns
    -------
    Union[bool, str]
        True if successful, error message string if failed.

    Examples
    --------
    # Add a new row to a table
    old = "| TKT-1056  | 2024-09-25 | Late Delivery   | Resolved |"
    new = "| TKT-1056  | 2024-09-25 | Late Delivery   | Resolved |\\n| TKT-1057  | 2024-11-11 | Damaged Item    | Open     |"
    result = update_file("user.md", old, new)
    """
    try:
        # Resolve relative paths relative to agent's working_dir
        normalized = normalize_agent_path(file_path)
        if normalized is None:
            return f"Error: Invalid path resolution for {file_path}"
        file_path = normalized

        # Now convert to absolute path for scope validation
        abs_path = os.path.abspath(file_path)

        # Scope validation
        agent = get_current_agent()
        if agent and hasattr(agent, "restricted_scope") and agent.restricted_scope:
            if not any(abs_path.startswith(allowed) for allowed in agent.allowed_paths):
                return f"Error: Access denied. File '{file_path}' is outside assigned scope."

        # Read the current file content
        if not os.path.exists(abs_path):
            return f"Error: File '{file_path}' does not exist"

        if not os.path.isfile(abs_path):
            return f"Error: '{file_path}' is not a file"

        with open(abs_path, "r") as f:
            current_content = f.read()

        # Check if old_content exists in the file
        if old_content not in current_content:
            # Provide helpful context about what wasn't found
            preview_length = 50
            preview = (
                old_content[:preview_length] + "..."
                if len(old_content) > preview_length
                else old_content
            )
            return f"Error: Could not find the specified content in the file. Looking for: '{preview}'"

        # Perform the replacement (only first occurrence)
        updated_content = current_content.replace(old_content, new_content, 1)

        # Check if replacement actually changed anything
        if updated_content == current_content:
            return "Error: No changes were made to the file"

        # Write the updated content back
        with open(abs_path, "w") as f:
            f.write(updated_content)

        return True

    except PermissionError:
        return f"Error: Permission denied writing to '{file_path}'"
    except Exception as e:
        return f"Error: Unexpected error - {str(e)}"


def create_file(file_path: str, content: str = "") -> bool:
    """
    Create a new file in the file system with the given content (if any).
    If the file already exists, overwrite it with the new content.

    Args:
        file_path: The path to the file.
        content: The content of the file.

    Returns:
        True if the file was created successfully, False otherwise.
    """
    temp_file_path = None
    try:
        # Resolve relative paths relative to agent's working_dir
        normalized = normalize_agent_path(file_path)
        if normalized is None:
            raise Exception(f"Error: Invalid path resolution for {file_path}")
        file_path = normalized

        # Now convert to absolute path for scope validation
        abs_path = os.path.abspath(file_path)

        # Scope validation
        agent = get_current_agent()
        if agent and hasattr(agent, "restricted_scope") and agent.restricted_scope:
            if not any(abs_path.startswith(allowed) for allowed in agent.allowed_paths):
                raise Exception(
                    f"Error: Access denied. File '{file_path}' is outside assigned scope."
                )

        # Create parent directories if they don't exist
        parent_dir = os.path.dirname(abs_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        # Create a unique temporary file name in the same directory as the target file
        # This ensures the temp file is within the sandbox's allowed path
        target_dir = os.path.dirname(abs_path) or "."
        temp_file_path = os.path.join(target_dir, f"temp_{uuid.uuid4().hex[:8]}.txt")

        with open(temp_file_path, "w") as f:
            f.write(content)

        # Move the content to the final destination
        with open(abs_path, "w") as f:
            f.write(content)
        os.remove(temp_file_path)
        return True
    except Exception as e:
        # Clean up temp file if it exists
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception:
                pass
        raise Exception(f"Error creating file {file_path}: {e}")
