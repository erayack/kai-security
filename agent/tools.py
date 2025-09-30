import os
import tempfile
import uuid
import json
import subprocess
from pathlib import Path
from typing import Union, Optional

from agent.schemas import GrepResponse, Exploit
from agent.settings import EXPLOITS_PATH

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

def grep(args: str) -> GrepResponse:
    """
    Run system grep with the provided CLI-style arg string.
    Prints output passthrough; returns grep's exit code (0/1/2).

    Args:
        args: The arguments to pass to grep.
    Returns:
        A GrepResponse object. This object has the fields exit_code, 
        stdout, and stderr. stdout and stderr are the output of the 
        grep command, and exit_code is the exit code of the grep 
        command.
    """
    try:
        p = subprocess.run(f"grep {args}", shell=True, text=True, capture_output=True)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, f"Error: {e}", ""


def add_exploit(exploit: Exploit) -> str:
    """
    Add an exploit to the exploits.json file.

    Args:
        exploit: The exploit to add.

    Returns:
        A string indicating whether the exploit 
        was added successfully or not.
    """
    try:
        path = Path(EXPLOITS_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch(exist_ok=True)

        try:
            raw = path.read_text(encoding="utf-8") if path.stat().st_size else ""
            data = json.loads(raw) if raw else []
            exploits = (
                data if isinstance(data, list)
                else [data] if isinstance(data, dict)
                else []
            )
        except Exception:
            exploits = []

        new_data = exploits + [exploit.model_dump()]
        with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding="utf-8") as tmp:
            json.dump(new_data, tmp)
            tmp.flush()
            os.fsync(tmp.fileno())
            temp_name = tmp.name
        os.replace(temp_name, path)
    except Exception as e:
        return f"Error: {e}"
    return "Exploit added successfully"
