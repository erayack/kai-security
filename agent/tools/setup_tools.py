import os
import tempfile
import uuid
import json
import subprocess
from pathlib import Path
from typing import Union, Optional, List

from agent.schemas import GrepResponse, Exploit, ExploitLocation, ExploitSeverity
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

def forge_install(package_name: str, working_dir: Optional[str] = None) -> str:
    """
    Install a package using forge.

    Args:
        package_name: The name of the package to install.
        working_dir: The directory to run the forge install command from. 
                    Useful for repos with multiple sub-projects.
                    If None, uses the current working directory.

    Returns:
        A string containing the output of the forge install command.
        
    Examples:
        # Install in a sub-repository
        forge_install("openzeppelin/openzeppelin-contracts", working_dir="ve33")
    """
    try:
        result = subprocess.run(
            ["forge", "install", package_name],
            check=True,
            capture_output=True,
            text=True,
            cwd=working_dir
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"

def forge_build(working_dir: Optional[str] = None) -> str:
    """
    Build the project using forge.

    Args:
        working_dir: The directory to run the forge build command from.
                    Useful for repos with multiple sub-projects.
                    If None, uses the current working directory.

    Returns:
        A string containing the output of the forge build command.
        
    Examples:
        # Build a sub-repository
        forge_build(working_dir="ve33")
        
        # Build from current directory
        forge_build()
    """
    try:
        result = subprocess.run(
            ["forge", "build"],
            check=True,
            capture_output=True,
            text=True,
            cwd=working_dir
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"

def npm_install(working_dir: Optional[str] = None) -> str:
    """
    Install npm dependencies for the project.
    
    Many Solidity projects use npm packages (like @openzeppelin/contracts)
    that need to be installed before compilation.

    Args:
        working_dir: The directory to run npm install from.
                    Useful for repos with multiple sub-projects.
                    If None, uses the current working directory.

    Returns:
        A string containing the output of the npm install command.
        
    Examples:
        # Install npm dependencies in a sub-repository
        npm_install(working_dir="ve33")
        
        # Install in current directory
        npm_install()
    """
    try:
        result = subprocess.run(
            ["npm", "install"],
            check=True,
            capture_output=True,
            text=True,
            cwd=working_dir
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"