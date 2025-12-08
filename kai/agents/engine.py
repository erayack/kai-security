import base64
import builtins
import importlib
import logging
import os
import pickle
import subprocess
import sys
import threading
import traceback
import warnings

from typing import Optional
from kai.agents.settings import SANDBOX_TIMEOUT

# Filter out event loop cleanup warnings (harmless during shutdown)
warnings.filterwarnings("ignore", message=".*Event loop is closed.*")
warnings.filterwarnings(
    "ignore", message=".*coroutine.*was never awaited.*", category=RuntimeWarning
)

# Suppress httpx/anyio cleanup warnings when event loop closes in threads
# These are harmless - the OS will clean up the connections
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("httpcore").setLevel(logging.ERROR)
logging.getLogger("anyio").setLevel(logging.ERROR)

# Global registry for agent instances (to avoid pickling)
_agent_registry = {}
_agent_registry_lock = threading.Lock()


def get_agent_from_registry(agent_id: str):
    """Get an agent instance from the registry by ID."""
    with _agent_registry_lock:
        return _agent_registry.get(agent_id)


def _run_user_code(
    code: str,
    allow_installs: bool,
    allowed_path: str,
    blacklist: list,
    available_functions: dict,
    log: bool = False,
    agent_id: Optional[str] = None,
) -> tuple[dict, str]:
    """
    Execute code under sandboxed conditions (limited file access, optional installs,
    and blacklisting) and return the resulting locals and an error message.
    """
    try:
        # Optional: apply working directory and file access restriction
        if allowed_path:
            allowed = os.path.abspath(allowed_path)
            try:
                os.chdir(allowed)  # Change working dir to the allowed_path
            except Exception as e:
                # If we cannot chdir, log but continue (the open wrapper will still enforce path)
                logging.warning(
                    "Could not change working directory to %s: %s", allowed, e
                )
            # Wrap builtins.open to restrict file access
            orig_open = builtins.open

            def secure_open(file, *args, **kwargs):
                """Open that restricts file access to allowed_path."""
                # If file is a file object or path-like, get its string path
                path = (
                    file if isinstance(file, str) else getattr(file, "name", str(file))
                )
                full_path = os.path.abspath(path if path is not None else "")
                if not full_path.startswith(allowed):
                    raise PermissionError(
                        f"Access to '{full_path}' is denied by sandbox."
                    )
                return orig_open(file, *args, **kwargs)

            builtins.open = secure_open

            # Optionally, restrict other file-related functions (remove, rename, etc.) similarly
            # We'll patch a couple of common ones as an example:
            orig_remove = os.remove

            def secure_remove(path, *args, **kwargs):
                full_path = os.path.abspath(path)
                if not full_path.startswith(allowed):
                    raise PermissionError(
                        f"Removal of '{full_path}' is denied by sandbox."
                    )
                return orig_remove(path, *args, **kwargs)

            os.remove = secure_remove

            orig_rename = os.rename

            def secure_rename(src, dst, *args, **kwargs):
                full_src = os.path.abspath(src)
                full_dst = os.path.abspath(dst)
                if not full_src.startswith(allowed) or not full_dst.startswith(allowed):
                    raise PermissionError(
                        "Rename operation outside allowed path is denied by sandbox."
                    )
                return orig_rename(src, dst, *args, **kwargs)

            os.rename = secure_rename

        # Apply blacklist restrictions by removing or disabling blacklisted builtins or attributes
        if blacklist:
            for name in blacklist:
                # If the name has a dot, like "os.system", handle module attributes
                if "." in name:
                    mod_name, attr_name = name.split(".", 1)
                    try:
                        mod_obj = importlib.import_module(mod_name)
                    except ImportError:
                        mod_obj = None
                    # If module is imported in sandbox, remove the attribute
                    if mod_obj and hasattr(mod_obj, attr_name):
                        try:
                            setattr(
                                mod_obj, attr_name, None
                            )  # simple way: nullify the attribute
                        except Exception:
                            pass  # if we cannot set it, ignore (might be read-only)
                else:
                    # It's a built-in or global name; remove from builtins if present
                    if name in builtins.__dict__:
                        builtins.__dict__[name] = (
                            None  # or we could del, but setting None prevents use
                        )
            # Additionally, we can ensure __builtins__ in the exec env doesn't contain them (handled below in exec)

        # If allowed, handle package installations inside sandbox (in case code itself triggers ImportError)
        if allow_installs:
            # We will install missing imports on the fly during execution if an ImportError occurs.
            # One approach: wrap __import__ to catch failed imports and pip install.
            orig_import = builtins.__import__

            def custom_import(name, globals=None, locals=None, fromlist=(), level=0):
                try:
                    return orig_import(name, globals, locals, fromlist, level)
                except ImportError as e:
                    pkg = name.split(".")[0]
                    logging.info(
                        "Sandbox: attempting to install missing package '%s'", pkg
                    )
                    try:
                        subprocess.run(
                            [sys.executable, "-m", "pip", "install", pkg],
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    except Exception as inst_err:
                        # If installation fails, re-raise the original ImportError
                        logging.error(
                            "Sandbox: failed to install package %s: %s", pkg, inst_err
                        )
                        raise e
                    # Retry the import after installation
                    return orig_import(name, globals, locals, fromlist, level)

            builtins.__import__ = custom_import

        # Prepare an isolated execution namespace. We use an empty globals dict with a fresh builtins.
        exec_globals = {"__builtins__": builtins.__dict__}

        # Add any provided functions to the execution environment
        if available_functions:
            exec_globals.update(available_functions)

        # Add agent accessor function if agent_id provided
        if agent_id:
            exec_globals["_get_current_agent"] = lambda: get_agent_from_registry(
                agent_id
            )
            exec_globals["_agent_id"] = agent_id
            exec_globals["_agent_instance"] = get_agent_from_registry(agent_id)

        exec_locals = {}  # local variables will be collected here

        error_msg = None
        try:
            exec(code, exec_globals, exec_locals)  # Execute the user's code
        except Exception as e:
            # Catch any exception and format it
            tb = traceback.format_exc()
            error_msg = f"Exception in sandboxed code:\n{tb}"
            if log:
                logging.error("Sandbox: code raised an exception: %s", e)
        except SystemExit as e:
            # Handle sys.exit calls (which raise SystemExit)
            code_val = e.code if isinstance(e.code, int) or e.code else 0
            if code_val != 0:
                error_msg = f"Sandboxed code called sys.exit({code_val})"
                if log:
                    logging.warning(
                        "Sandbox: code exited with non-zero status %s", code_val
                    )
            # For sys.exit(0), we treat it as normal termination (no error)

        # Clean up any blacklisted or internal entries in locals
        exec_locals.pop("__builtins__", None)

        # Collect only picklable locals for returning
        safe_locals = {}
        for var, val in exec_locals.items():
            try:
                pickle.dumps(val)  # test picklability
                safe_locals[var] = val
            except Exception:
                safe_locals[var] = repr(val)  # fallback: use string representation

        if log:
            logging.info("Sandbox execution finished")

        return safe_locals, error_msg

    except Exception as e:
        # Catch any unhandled exceptions in the worker process
        if log:
            logging.error(
                "Unhandled exception in sandbox worker: %s", traceback.format_exc()
            )
        return {}, f"Sandbox worker error: {str(e)}"


async def _execute_with_delegation_async(
    code: str,
    allowed_path: str,
    import_module: str,
    agent_instance,
) -> tuple[dict, str]:
    """
    Execute async code directly in the current event loop (used when agent calls async tools).
    """
    import asyncio

    try:
        # Import the tools module
        shared_tools_module = None
        try:
            shared_tools_module = importlib.import_module("kai.agents.tools.tools")
        except Exception:
            shared_tools_module = None

        def _agent_provider():
            return agent_instance

        available_functions = {}
        if import_module:
            module = importlib.import_module(import_module)
            module.__dict__["_get_current_agent"] = _agent_provider
            for name in dir(module):
                if not name.startswith("_"):
                    attr = getattr(module, name)
                    if callable(attr):
                        available_functions[name] = attr
        if shared_tools_module:
            shared_tools_module.__dict__["_get_current_agent"] = _agent_provider
        # Add agent accessor and asyncio
        available_functions["_get_current_agent"] = lambda: agent_instance
        available_functions["asyncio"] = asyncio

        # DON'T change directory - it's not thread-safe and causes conflicts
        # Instead, ensure agent's working_dir is used by tools via agent instance

        # Execute code in async context with stdout/stderr captured
        exec_globals = {"__builtins__": __builtins__}
        exec_globals.update(available_functions)
        exec_globals["_agent_instance"] = agent_instance
        exec_locals = {}

        # Capture stdout/stderr to suppress agent's print statements
        import io

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        try:
            # Check if code contains await
            has_await = "await " in code

            if has_await:
                # Wrap in async function and await it
                async_code = f"""
async def _async_wrapper():
{chr(10).join("    " + line for line in code.split(chr(10)))}
    return locals()
"""
                exec(async_code, exec_globals, exec_locals)
                result_locals = await exec_locals["_async_wrapper"]()
                exec_locals.update(result_locals)
            else:
                # Sync code - execute normally
                code_stripped = code.strip()
                lines = [
                    line
                    for line in code_stripped.split("\n")
                    if line.strip() and not line.strip().startswith("#")
                ]

                if len(lines) == 1:
                    try:
                        result = eval(code_stripped, exec_globals, exec_locals)
                        if result is not None:
                            exec_locals["_last_result"] = result
                    except SyntaxError:
                        exec(code, exec_globals, exec_locals)
                else:
                    exec(code, exec_globals, exec_locals)
        finally:
            # Restore stdout/stderr
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        # Filter out non-picklable objects
        safe_locals = {}
        for var, val in exec_locals.items():
            try:
                pickle.dumps(val)
                safe_locals[var] = val
            except Exception:
                safe_locals[var] = repr(val)

        return safe_locals, ""
    except Exception as e:
        tb = traceback.format_exc()
        return {}, f"Exception in code execution:\n{tb}"


def _execute_with_delegation(
    code: str,
    allowed_path: str,
    import_module: str,
    agent_instance,
) -> tuple[dict, str]:
    """
    Sync wrapper that runs async execution in a new thread with its own event loop.
    """
    import asyncio
    import threading

    result_container = []
    exception_container = []

    def run_in_thread():
        loop = None
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Set custom exception handler to suppress harmless cleanup errors
            def handle_exception(loop, context):
                exception = context.get("exception")
                message = context.get("message", "")

                # Suppress "Event loop is closed" errors from httpx/anyio cleanup
                # These happen when httpx tries to close connections after the loop is closed
                # They're harmless - the OS will clean up the connections
                if isinstance(
                    exception, RuntimeError
                ) and "Event loop is closed" in str(exception):
                    return

                # For other exceptions, use default handling
                loop.default_exception_handler(context)

            loop.set_exception_handler(handle_exception)

            # Run the main async function
            result = loop.run_until_complete(
                _execute_with_delegation_async(
                    code, allowed_path, import_module, agent_instance
                )
            )
            result_container.append(result)

        except Exception as e:
            exception_container.append(e)
        finally:
            # Clean shutdown of the event loop
            if loop is not None:
                try:
                    # Give httpx and other libraries time to schedule their cleanup tasks
                    # This is crucial because AsyncClient.aclose() schedules cleanup but doesn't block
                    loop.run_until_complete(asyncio.sleep(0.1))
                except Exception:
                    pass

                # Now wait for ALL pending tasks to complete
                max_cleanup_attempts = 3
                for attempt in range(max_cleanup_attempts):
                    try:
                        pending = asyncio.all_tasks(loop)
                        if not pending:
                            break

                        # Wait for all pending tasks with a timeout
                        loop.run_until_complete(
                            asyncio.wait_for(
                                asyncio.gather(*pending, return_exceptions=True),
                                timeout=2.0,
                            )
                        )
                    except asyncio.TimeoutError:
                        # If tasks don't complete, cancel them
                        pending = asyncio.all_tasks(loop)
                        for task in pending:
                            task.cancel()
                        # Give cancelled tasks a moment to finish cancelling
                        try:
                            loop.run_until_complete(
                                asyncio.gather(*pending, return_exceptions=True)
                            )
                        except Exception:
                            pass
                    except Exception:
                        pass

                # Shutdown async generators
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass

                # Shutdown default executor
                try:
                    loop.run_until_complete(loop.shutdown_default_executor())
                except Exception:
                    pass

                # Final delay to let the system finish any remaining cleanup
                try:
                    loop.run_until_complete(asyncio.sleep(0.1))
                except Exception:
                    pass

                # Check one more time for any straggler tasks
                try:
                    pending = asyncio.all_tasks(loop)
                    if pending:
                        for task in pending:
                            task.cancel()
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                except Exception:
                    pass

                # Finally, close the loop
                try:
                    loop.close()
                except Exception:
                    pass

    thread = threading.Thread(target=run_in_thread, daemon=False)
    thread.start()
    thread.join(SANDBOX_TIMEOUT)

    if thread.is_alive():
        # Thread is still running after timeout
        return {}, "Thread execution timed out"

    if exception_container:
        raise exception_container[0]

    if not result_container:
        return {}, "No result returned from thread"

    return result_container[0]


def execute_sandboxed_code(
    code: str,
    timeout: int = SANDBOX_TIMEOUT,
    allow_installs: bool = False,
    requirements_path: Optional[str] = None,
    allowed_path: Optional[str] = None,
    blacklist: Optional[list] = None,
    available_functions: Optional[dict] = None,
    import_module: Optional[str] = None,
    log: bool = False,
    agent_instance=None,  # NEW: Pass agent instance for sub-agent delegation
) -> tuple[dict, str]:
    """
    Execute the given Python code string in a sandboxed subprocess with specified restrictions.

    Parameters:
        code (str): The Python code to execute.
        timeout (int): Maximum execution time in seconds for the sandboxed code (default 10 seconds).
        allow_installs (bool): If True, allow installing missing packages via pip (default False).
        requirements_path (str): Path to a requirements.txt file to install before execution.
        allowed_path (str): Directory path that the code is allowed to access for file I/O.
                            File operations outside this path will be blocked. If None, no extra file restrictions are applied.
        blacklist (list): List of names (builtins or module attributes) that are disallowed in the code.
                          If the code uses any of these, it will be prevented or result in an error.
        available_functions (dict): Dictionary of functions to make available in the sandboxed environment.
                                   The keys are the function names, and the values are the function objects.
        import_module (str): Name of a Python module to import and make all its functions available in the sandbox.

    Returns:
        (dict, str): A tuple containing the dictionary of local variables from the executed code (or None on failure),
                     and an error message (str) if an error/exception occurred, or None if execution was successful.
    """
    # Step 1: If package installs are allowed, handle requirements and prepare environment
    if requirements_path:
        if os.path.isfile(requirements_path):
            logging.info(
                "Installing packages from requirements file: %s", requirements_path
            )
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", requirements_path],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                logging.error(
                    "Failed to install requirements from %s: %s", requirements_path, e
                )
                # If requirements fail to install, we can choose to abort or continue. Here, abort execution.
                return {}, f"Failed to install requirements: {e}"
        else:
            logging.error("Requirements file %s not found.", requirements_path)
            return {}, f"Requirements file not found: {requirements_path}"

    # Check if this is a sub-agent or code contains special functions - if so, execute in main process
    # Sub-agents need main process for proper tool function access
    # delegate_to_sub_agent and add_exploit need main process for HTTP clients
    if agent_instance is not None:
        # Always run in main process if agent instance is provided (handles sub-agents + special functions)
        return _execute_with_delegation(
            code, allowed_path, import_module, agent_instance
        )

    # If a module name is provided, import it and add its functions to available_functions
    if isinstance(available_functions, str) and not import_module:
        import_module = available_functions
        available_functions = None

    if import_module:
        try:
            module = importlib.import_module(import_module)
            if available_functions is None:
                available_functions = {}
            for name in dir(module):
                if not name.startswith("_"):
                    attr = getattr(module, name)
                    if callable(attr):
                        available_functions[name] = attr
        except ImportError as e:
            logging.error(f"Failed to import module {import_module}: {e}")
            return {}, f"Failed to import module {import_module}: {e}"

    # Add agent instance to registry and pass only the ID (NEW)
    agent_id = None
    if agent_instance is not None:
        # Register the agent in the global registry
        agent_id = agent_instance.agent_id
        with _agent_registry_lock:
            _agent_registry[agent_id] = agent_instance

    # Step 2: Execute the code in a separate Python subprocess
    params = {
        "code": code,
        "allow_installs": allow_installs,
        "allowed_path": allowed_path,
        "blacklist": blacklist or [],
        "available_functions": available_functions or {},
        "log": log,
        "agent_id": agent_id,  # Pass agent ID instead of instance
    }

    env = os.environ.copy()
    env["SANDBOX_PARAMS"] = base64.b64encode(pickle.dumps(params)).decode()

    try:
        result = subprocess.run(
            [sys.executable, "-m", "kai.agents.engine"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        logging.error(
            "Sandboxed code exceeded time limit of %d seconds; terminating.", timeout
        )
        # Clean up agent from registry
        if agent_id:
            with _agent_registry_lock:
                _agent_registry.pop(agent_id, None)
        return {}, f"TimeoutError: Code execution exceeded {timeout} seconds."

    if result.returncode != 0:
        # Clean up agent from registry
        if agent_id:
            with _agent_registry_lock:
                _agent_registry.pop(agent_id, None)
        return {}, result.stderr.decode().strip()

    try:
        local_vars, error_msg = pickle.loads(result.stdout)
    except Exception as e:
        # Clean up agent from registry
        if agent_id:
            with _agent_registry_lock:
                _agent_registry.pop(agent_id, None)
        return {}, f"Failed to decode sandbox output: {e}"

    if error_msg is None:
        error_msg = ""

    # Clean up agent from registry after successful execution
    if agent_id:
        with _agent_registry_lock:
            _agent_registry.pop(agent_id, None)

    return local_vars, error_msg


def _subprocess_entry() -> None:
    """Entry point for sandbox subprocess."""
    params_b64 = os.environ.get("SANDBOX_PARAMS")
    if not params_b64:
        sys.exit(1)
    params = pickle.loads(base64.b64decode(params_b64))
    locals_dict, error = _run_user_code(
        params["code"],
        params.get("allow_installs", False),
        params.get("allowed_path"),
        params.get("blacklist", []),
        params.get("available_functions", {}),
        params.get("log", False),
        params.get("agent_id"),
    )
    sys.stdout.buffer.write(pickle.dumps((locals_dict, error)))


if __name__ == "__main__":
    _subprocess_entry()
