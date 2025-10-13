import os
import json
import subprocess
import uuid
from typing import Optional, Union

def read_file(file_path: str) -> str:
    """
    Read a file with a given path.

    Args:
        file_path: The path to the file.

    Returns:
        The content of the file, or an error message if the file cannot be read.
    """
    try:
        # Ensure the file path is properly resolved
        if not os.path.exists(file_path):
            return f"Error: File {file_path} does not exist"
        
        if not os.path.isfile(file_path):
            return f"Error: {file_path} is not a file"
            
        with open(file_path, "r") as f:
            return f.read()
    except PermissionError:
        return f"Error: Permission denied accessing {file_path}"
    except Exception as e:
        return f"Error: {e}"

def list_files(path: Optional[str] = None) -> str:
    """
    Display all files and directories in the current working directory as a tree structure. If given a path, display the files and directories in the given path.
    
    Example output:
    ```
    ./
    ├── user.md
    └── entities/
        ├── 452_willow_creek_dr.md
        └── frank_miller_plumbing.md
    ```

    Args:
        [Optional] path: The path to the directory to display.

    Returns:
        A string representation of the directory tree.
    """
    try:
        # Always use current working directory
        dir_path = os.getcwd() if path is None else path
        
        def build_tree(start_path, prefix="", is_last=True):
            """Recursively build tree structure"""
            entries = []
            try:
                items = sorted(os.listdir(start_path))
                # Filter out hidden files and __pycache__
                items = [item for item in items if not item.startswith('.') and item != '__pycache__']
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
                    # Check if directory is empty
                    try:
                        dir_contents = [f for f in os.listdir(item_path) 
                                      if not f.startswith('.') and f != '__pycache__']
                        if not dir_contents:
                            entries.append(f"{current_prefix}{item}/ (empty)\n")
                        else:
                            entries.append(f"{current_prefix}{item}/\n")
                            # Recursively add subdirectory contents
                            entries.append(build_tree(item_path, extension, is_last_item))
                    except PermissionError:
                        entries.append(f"{current_prefix}{item}/ [Permission Denied]\n")
                else:
                    entries.append(f"{current_prefix}{item}\n")
            
            return "".join(entries)
        
        # Start with the root directory
        tree = f"./\n{build_tree(dir_path)}"
        return tree.rstrip()  # Remove trailing newline
        
    except Exception as e:
        return f"Error: {e}"

def grep(args: str) -> tuple:
    """
    Run system grep with the provided CLI-style arg string.
    Prints output passthrough; returns grep's exit code (0/1/2).

    Args:
        args: The arguments to pass to grep.
    Returns:
        A tuple of (exit_code, stdout, stderr).
    """
    try:
        p = subprocess.run(f"grep {args}", shell=True, text=True, capture_output=True)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, f"Error: {e}", ""

def run_test(test_script_path: str) -> dict:
    """
    Run the command: `forge test --match-path test_script_path --json`

    Args:
        test_script_path: The path to the test script.

    Returns:
        A dictionary containing the test results.
    """
    try:
        p = subprocess.run(f"forge test --match-path {test_script_path} --json", shell=True, text=True, capture_output=True)
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        # If JSON parsing fails, return the raw stdout
        return {"stdout": p.stdout}
    except Exception as e:
        return {"error": str(e)}

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
        # Read the current file content
        if not os.path.exists(file_path):
            return f"Error: File '{file_path}' does not exist"

        if not os.path.isfile(file_path):
            return f"Error: '{file_path}' is not a file"

        with open(file_path, "r") as f:
            current_content = f.read()

        # Check if old_content exists in the file
        if old_content not in current_content:
            # Provide helpful context about what wasn't found
            preview_length = 50
            preview = old_content[:preview_length] + "..." if len(old_content) > preview_length else old_content
            return f"Error: Could not find the specified content in the file. Looking for: '{preview}'"

        # Count occurrences to warn about multiple matches
        occurrences = current_content.count(old_content)
        if occurrences > 1:
            # Still proceed but warn the user
            print(f"Warning: Found {occurrences} occurrences of the content. Replacing only the first one.")

        # Perform the replacement (only first occurrence)
        updated_content = current_content.replace(old_content, new_content, 1)

        # Check if replacement actually changed anything
        if updated_content == current_content:
            return "Error: No changes were made to the file"

        # Write the updated content back
        with open(file_path, "w") as f:
            f.write(updated_content)

        return True

    except PermissionError:
        return f"Error: Permission denied writing to '{file_path}'"
    except Exception as e:
        return f"Error: Unexpected error - {str(e)}"