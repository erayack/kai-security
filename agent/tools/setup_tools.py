import os
import tempfile
import uuid
import json
import subprocess
from pathlib import Path
from typing import Union, Optional, List

from agent.schemas import GrepResponse, Exploit, ExploitLocation, ExploitSeverity
from agent.settings import EXPLOITS_PATH
from agent.tools.tools import read_file, list_files, cargo_test, anchor_test

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

def forge_build(
    working_dir: Optional[str] = None,
    force: bool = False,
    skip: Optional[List[str]] = None,
    sizes: bool = False,
    names: bool = False,
    additional_args: Optional[str] = None
) -> str:
    """
    Build the project using forge.

    Args:
        working_dir: The directory to run the forge build command from.
                    Useful for repos with multiple sub-projects.
                    If None, uses the current working directory.
        force: If True, clears the cache and recompiles all contracts (--force flag).
        skip: List of file paths or patterns to skip during compilation.
              For example: ["test/", "script/Deploy.sol"]
        sizes: If True, displays contract sizes after compilation (--sizes flag).
        names: If True, prints compiled contract names (--names flag).
        additional_args: Any additional forge build arguments as a string.
                        For example: "--optimize --optimizer-runs 200"

    Returns:
        A string containing the output of the forge build command.
        
    Examples:
        # Build a sub-repository
        forge_build(working_dir="ve33")
        
        # Build from current directory
        forge_build()
        
        # Force rebuild with sizes
        forge_build(force=True, sizes=True)
        
        # Skip test directory
        forge_build(skip=["test/"])
        
        # Build with custom optimizer settings
        forge_build(additional_args="--optimize --optimizer-runs 200")
    """
    try:
        # Build the forge build command
        cmd = ["forge", "build"]
        
        # Add force flag if requested
        if force:
            cmd.append("--force")
        
        # Add skip patterns if specified
        if skip:
            for pattern in skip:
                cmd.extend(["--skip", pattern])
        
        # Add sizes flag if requested
        if sizes:
            cmd.append("--sizes")
        
        # Add names flag if requested
        if names:
            cmd.append("--names")
        
        # Add any additional arguments
        if additional_args:
            cmd.extend(additional_args.split())
        
        result = subprocess.run(
            cmd,
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

def cargo_install(crate_name: str, version: Optional[str] = None, working_dir: Optional[str] = None) -> str:
    """
    Install a Rust crate using cargo.
    
    This is useful for installing command-line tools and dependencies 
    that are distributed as Rust crates.

    Args:
        crate_name: The name of the crate to install.
        version: Optional version of the crate to install.
                If None, installs the latest version.
        working_dir: The directory to run cargo install from.
                    If None, uses the current working directory.

    Returns:
        A string containing the output of the cargo install command.
        
    Examples:
        # Install the latest version of a crate
        cargo_install("ripgrep")
        
        # Install a specific version
        cargo_install("cargo-edit", version="0.12.0")
        
        # Install from a specific directory
        cargo_install("my-tool", working_dir="rust-project")
    """
    try:
        command = ["cargo", "install", crate_name]
        if version:
            command.extend(["--version", version])
        
        result = subprocess.run(
            command,
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
