import ast
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any

from ra.core.comms_utils import LMRequest, send_lm_request, send_lm_request_batched
from ra.core.types import REPLResult, RLMChatCompletion, SpawnRecord
from ra.environments.base_env import NonIsolatedEnv

# =============================================================================
# Safe Builtins
# =============================================================================

# Safe builtins - blocks dangerous operations like eval/exec/input
_SAFE_BUILTINS = {
    # Core types and functions
    "print": print,
    "len": len,
    "str": str,
    "int": int,
    "float": float,
    "list": list,
    "dict": dict,
    "set": set,
    "tuple": tuple,
    "bool": bool,
    "type": type,
    "isinstance": isinstance,
    "issubclass": issubclass,
    "enumerate": enumerate,
    "zip": zip,
    "map": map,
    "filter": filter,
    "sorted": sorted,
    "reversed": reversed,
    "range": range,
    "min": min,
    "max": max,
    "sum": sum,
    "abs": abs,
    "round": round,
    "any": any,
    "all": all,
    "pow": pow,
    "divmod": divmod,
    "chr": chr,
    "ord": ord,
    "hex": hex,
    "bin": bin,
    "oct": oct,
    "repr": repr,
    "ascii": ascii,
    "format": format,
    "hash": hash,
    "id": id,
    "iter": iter,
    "next": next,
    "slice": slice,
    "callable": callable,
    "hasattr": hasattr,
    "getattr": getattr,
    "setattr": setattr,
    "delattr": delattr,
    "dir": dir,
    "vars": vars,
    "bytes": bytes,
    "bytearray": bytearray,
    "memoryview": memoryview,
    "complex": complex,
    "object": object,
    "super": super,
    "property": property,
    "staticmethod": staticmethod,
    "classmethod": classmethod,
    "__import__": __import__,
    "open": open,
    # Exceptions
    "Exception": Exception,
    "BaseException": BaseException,
    "ValueError": ValueError,
    "TypeError": TypeError,
    "KeyError": KeyError,
    "IndexError": IndexError,
    "AttributeError": AttributeError,
    "FileNotFoundError": FileNotFoundError,
    "OSError": OSError,
    "IOError": IOError,
    "RuntimeError": RuntimeError,
    "NameError": NameError,
    "ImportError": ImportError,
    "StopIteration": StopIteration,
    "AssertionError": AssertionError,
    "NotImplementedError": NotImplementedError,
    "ArithmeticError": ArithmeticError,
    "LookupError": LookupError,
    "Warning": Warning,
    # Blocked
    "input": None,
    "eval": None,
    "exec": None,
    "compile": None,
    "globals": None,
    "locals": None,
}


class LocalREPL(NonIsolatedEnv):
    """
    Local REPL environment with persistent Python namespace.
    Executes code in a sandboxed namespace with access to context data.
    """

    def __init__(
        self,
        lm_handler_address: tuple[str, int] | None = None,
        context_payload: dict | list | str | None = None,
        setup_code: str | None = None,
        persistent: bool = False,
        depth: int = 1,
        tools: dict[str, Any] | None = None,
        **kwargs,
    ):
        factory = kwargs.pop("workspace_factory", None)
        self._query_model: str | None = kwargs.pop("query_model", None)
        super().__init__(persistent=persistent, depth=depth, **kwargs)

        self.lm_handler_address = lm_handler_address
        self.original_cwd = os.getcwd()
        if factory is not None:
            self.temp_dir = factory()
        else:
            self.temp_dir = tempfile.mkdtemp(prefix=f"repl_env_{uuid.uuid4()}_")
        self._lock = threading.Lock()
        self._context_count: int = 0
        self._history_count: int = 0
        self._tools: dict[str, Any] = tools or {}

        # Setup globals, locals, and modules in environment.
        self.setup()

        # Load context if provided
        if context_payload is not None:
            self.load_context(context_payload)

        # Run setup code if provided
        if setup_code:
            self.execute_code(setup_code)

    def setup(self):
        """Setup the environment."""
        # Create sandboxed globals
        self.globals: dict[str, Any] = {
            "__builtins__": _SAFE_BUILTINS.copy(),
            "__name__": "__main__",
        }
        self.locals: dict[str, Any] = {}

        # Track LLM calls made during code execution
        self._pending_llm_calls: list[RLMChatCompletion] = []

        # Add helper functions
        self.globals["FINAL_VAR"] = self._final_var
        self.globals["llm_query"] = self._llm_query
        self.globals["llm_query_batched"] = self._llm_query_batched

        # Inject agent tools into namespace
        for name, fn in self._tools.items():
            self.globals[name] = fn

    def _final_var(self, variable_name: str | object) -> str:
        """Return the value of a variable as a final answer."""
        import json

        # Handle FINAL_VAR(obj) where the value is passed directly
        if not isinstance(variable_name, str):
            value = variable_name
        else:
            variable_name = variable_name.strip().strip("\"'")
            if variable_name not in self.locals:
                return f"Error: Variable '{variable_name}' not found"
            value = self.locals[variable_name]

        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)

    def _llm_query(
        self, prompt: str, model: str | None = None, *, _retries: int = 1
    ) -> str:
        """Query the LM via socket connection to the handler.

        Retries once on failure or empty response.
        """
        if self.lm_handler_address is None:
            return "Error: No LM handler configured"

        if model is None:
            model = self._query_model

        try:
            request = LMRequest(prompt=prompt, model=model, depth=self.depth)
            response = send_lm_request(self.lm_handler_address, request)

            if not response.success:
                if _retries > 0:
                    return self._llm_query(prompt, model, _retries=0)
                return f"Error: {response.error}"

            assert response.chat_completion is not None
            self._pending_llm_calls.append(response.chat_completion)

            text = response.chat_completion.response
            if not text:
                if _retries > 0:
                    return self._llm_query(prompt, model, _retries=0)
                return "Error: LLM returned empty response"
            return text
        except Exception as e:
            if _retries > 0:
                return self._llm_query(prompt, model, _retries=0)
            return f"Error: LM query failed - {e}"

    def _llm_query_batched(
        self, prompts: list[str | dict[str, Any]], model: str | None = None
    ) -> list[str]:
        """Query the LM with multiple prompts concurrently.

        Args:
            prompts: List of prompts to send to the LM.
            model: Optional model name to use (if handler has multiple clients).

        Returns:
            List of responses in the same order as input prompts.
        """
        if self.lm_handler_address is None:
            return ["Error: No LM handler configured"] * len(prompts)

        try:
            responses = send_lm_request_batched(
                self.lm_handler_address, prompts, model=model, depth=self.depth
            )

            results = []
            for response in responses:
                if not response.success:
                    results.append(f"Error: {response.error}")
                else:
                    assert response.chat_completion is not None
                    self._pending_llm_calls.append(response.chat_completion)
                    text = response.chat_completion.response
                    if not text:
                        results.append("Error: LLM returned empty response")
                    else:
                        results.append(text)

            return results
        except Exception as e:
            return [f"Error: LM query failed - {e}"] * len(prompts)

    def load_context(self, context_payload: dict | list | str):
        """Load context into the environment as context_0 (and 'context' alias)."""
        self.add_context(context_payload, 0)

    def add_context(
        self, context_payload: dict | list | str, context_index: int | None = None
    ) -> int:
        """
        Add a context with versioned variable name.

        Args:
            context_payload: The context data to add
            context_index: Optional explicit index. If None, auto-increments.

        Returns:
            The context index used.
        """
        if context_index is None:
            context_index = self._context_count

        var_name = f"context_{context_index}"

        if isinstance(context_payload, str):
            context_path = os.path.join(self.temp_dir, f"context_{context_index}.txt")
            with open(context_path, "w") as f:
                f.write(context_payload)
            self.execute_code(
                f"with open(r'{context_path}', 'r') as f:\n    {var_name} = f.read()"
            )
        else:
            context_path = os.path.join(self.temp_dir, f"context_{context_index}.json")
            with open(context_path, "w") as f:
                json.dump(context_payload, f)
            self.execute_code(
                f"import json\nwith open(r'{context_path}', 'r') as f:\n    {var_name} = json.load(f)"
            )

        # Alias context_0 as 'context' for backward compatibility
        if context_index == 0:
            self.execute_code(f"context = {var_name}")

        self._context_count = max(self._context_count, context_index + 1)
        return context_index

    def update_handler_address(self, address: tuple[str, int]) -> None:
        """Update the LM handler address for a new completion call."""
        self.lm_handler_address = address

    def get_context_count(self) -> int:
        """Return the number of contexts loaded."""
        return self._context_count

    def add_history(
        self, message_history: list[dict[str, Any]], history_index: int | None = None
    ) -> int:
        """
        Store a conversation's message history as a versioned variable.

        Args:
            message_history: The list of message dicts from a completion call
            history_index: Optional explicit index. If None, auto-increments.

        Returns:
            The history index used.
        """
        if history_index is None:
            history_index = self._history_count

        var_name = f"history_{history_index}"

        # Store deep copy to avoid reference issues with nested dicts
        self.locals[var_name] = copy.deepcopy(message_history)

        # Alias history_0 as 'history' for convenience
        if history_index == 0:
            self.locals["history"] = self.locals[var_name]

        self._history_count = max(self._history_count, history_index + 1)
        return history_index

    def get_history_count(self) -> int:
        """Return the number of conversation histories stored."""
        return self._history_count

    @contextmanager
    def _capture_output(self):
        """Thread-safe context manager to capture stdout/stderr."""
        with self._lock:
            old_stdout, old_stderr = sys.stdout, sys.stderr
            stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
            try:
                sys.stdout, sys.stderr = stdout_buf, stderr_buf
                yield stdout_buf, stderr_buf
            finally:
                sys.stdout, sys.stderr = old_stdout, old_stderr

    @contextmanager
    def _temp_cwd(self):
        """Temporarily change to temp directory for execution."""
        old_cwd = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            yield
        finally:
            os.chdir(old_cwd)

    @staticmethod
    def _split_last_expr(code: str) -> tuple[str, str | None]:
        """Split code into body + trailing expression (if any).

        If the last statement is a bare expression (e.g. a function
        call whose return value isn't assigned), return (body, expr)
        so the caller can ``eval()`` the expression and auto-print
        the result — like interactive Python.
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return code, None
        if not tree.body:
            return code, None
        last = tree.body[-1]
        if not isinstance(last, ast.Expr):
            return code, None
        lines = code.splitlines(keepends=True)
        body = "".join(lines[: last.lineno - 1])
        expr = "".join(lines[last.lineno - 1 :]).strip()
        return body, expr

    _exec_timeout: int = int(os.environ.get("KAI_EXEC_TIMEOUT", 1200))

    @staticmethod
    def _find_assignment_targets(code: str) -> set[str]:
        """Return simple Name targets from all assignments in *code*.

        Handles plain assignments (``x = ...``), annotated assignments,
        and tuple/list unpacking (``a, b = ...``).  Attribute and
        subscript targets are silently skipped — they can't be
        recovered without the live object.
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return set()

        names: set[str] = set()

        def _collect(node: ast.AST) -> None:
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, (ast.Tuple, ast.List)):
                for elt in node.elts:
                    _collect(elt)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    _collect(target)
            elif isinstance(node, ast.AnnAssign) and node.target is not None:
                _collect(node.target)

        return names

    def _writeback_locals(
        self,
        namespace: dict[str, Any],
        targets: set[str],
        error_msg: str | None = None,
    ) -> None:
        """Write *namespace* back to ``self.locals``.

        If *error_msg* is provided, any assignment target not yet
        present in *namespace* receives the error string so downstream
        code sees the failure as a value rather than a ``NameError``.
        """
        if error_msg:
            for name in targets:
                if name not in namespace:
                    namespace[name] = error_msg

        for key, value in namespace.items():
            if key not in self.globals and not key.startswith("_"):
                self.locals[key] = value

    def execute_code(self, code: str) -> REPLResult:
        """Execute code in the persistent namespace and return result.

        If the last statement is a bare expression, its return value
        is auto-printed (like interactive Python / Jupyter).

        Execution is guarded by ``_exec_timeout`` (default 1200 s).
        On timeout the result contains a ``TimeoutError`` on stderr.

        On error or timeout, variables assigned before the failure are
        preserved and any unassigned targets receive the error string.
        """
        start_time = time.perf_counter()

        # Clear pending LLM calls from previous execution
        self._pending_llm_calls = []

        body, last_expr = self._split_last_expr(code)
        targets = self._find_assignment_targets(code)

        # Shared state between main thread and worker
        combined = {**self.globals, **self.locals}
        exc_holder: list[Exception] = []
        succeeded = False

        # Cooperative cancellation: stamp every tool so spawn functions
        # can forward the event to child RLM instances.
        # Bound methods don't support attribute assignment — skip them.
        cancel_event = threading.Event()
        for fn in self._tools.values():
            try:
                fn._cancel_event = cancel_event
            except AttributeError:
                pass

        with self._capture_output() as (stdout_buf, stderr_buf), self._temp_cwd():

            def _run() -> None:
                nonlocal succeeded
                try:
                    if body:
                        exec(body, combined, combined)

                    if last_expr is not None:
                        result = eval(  # noqa: S307
                            last_expr, combined, combined
                        )
                        if result is not None:
                            print(repr(result))

                    succeeded = True
                except Exception as e:
                    exc_holder.append(e)

            worker = threading.Thread(target=_run, daemon=True)
            worker.start()
            worker.join(timeout=self._exec_timeout)

            if worker.is_alive():
                # Signal child RLMs to stop at next iteration boundary
                cancel_event.set()
                # Timeout — worker is orphaned as a daemon thread
                stdout = stdout_buf.getvalue()
                error_msg = (
                    f"[error] TimeoutError: execution exceeded "
                    f"{self._exec_timeout}s limit"
                )
                stderr = stderr_buf.getvalue() + f"\n{error_msg}"
                # Snapshot: thread may still be running
                self._writeback_locals(dict(combined), targets, error_msg)
            elif exc_holder:
                stdout = stdout_buf.getvalue()
                e = exc_holder[0]
                error_msg = f"[error] {type(e).__name__}: {e}"
                stderr = stderr_buf.getvalue() + f"\n{error_msg}"
                # Thread has exited — safe to read combined
                self._writeback_locals(combined, targets, error_msg)
            else:
                self._writeback_locals(combined, targets)
                stdout = stdout_buf.getvalue()
                stderr = stderr_buf.getvalue()

        # Drain sub-agent completions and spawn records from tools
        spawn_records: list[SpawnRecord] = []
        for fn in self._tools.values():
            pending = getattr(fn, "_pending_completions", None)
            if pending:
                self._pending_llm_calls.extend(pending)
                pending.clear()
            records = getattr(fn, "_spawn_records", None)
            if records:
                spawn_records.extend(records)
                records.clear()

        return REPLResult(
            stdout=stdout,
            stderr=stderr,
            locals=self.locals.copy(),
            execution_time=time.perf_counter() - start_time,
            rlm_calls=self._pending_llm_calls.copy(),
            spawn_records=spawn_records,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    def cleanup(self):
        """Clean up temp directory and reset state."""
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass
        self.globals.clear()
        self.locals.clear()

    def __del__(self):
        self.cleanup()
