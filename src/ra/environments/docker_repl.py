"""
Docker REPL environment that runs Python code in a Docker container.

Setup:
    docker build -t rlm-sandbox -f Dockerfile.sandbox .

Or use any Python 3.11+ image with: pip install dill requests
"""

import ast
import base64
import copy
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from ra.core.comms_utils import (
    LMRequest,
    send_lm_request,
    send_lm_request_batched,
)
from ra.core.types import REPLResult, RLMChatCompletion, SpawnRecord
from ra.environments.base_env import NonIsolatedEnv

# =============================================================================
# Executor Script
# =============================================================================
# Written to /workspace/_executor.py inside the container at setup time.
# On each execute_code() call the host writes _exec_params.json with the
# code (base64), AST-split body/expr, assignment targets, proxy port, tool
# names, and query_model.  The executor reads the params, loads persisted
# state from state.dill, runs the code, and prints a JSON result line.
_EXECUTOR_SCRIPT = r'''import sys
import io
import json
import base64
import os

try:
    import dill
except ImportError:
    import pickle as dill

import requests

with open("/workspace/_exec_params.json") as _pf:
    _params = json.load(_pf)

_PROXY = f"http://host.docker.internal:{_params['proxy_port']}"
_STATE = "/workspace/state.dill"
_QUERY_MODEL = _params.get("query_model")


# ── LLM helpers ─────────────────────────────────────────────────

def llm_query(prompt, model=None, _retries=1):
    """Query the LM via the host proxy.  Retries once."""
    if model is None:
        model = _QUERY_MODEL
    try:
        r = requests.post(
            f"{_PROXY}/llm_query",
            json={"prompt": prompt, "model": model},
            timeout=300,
        )
        d = r.json()
        if d.get("error"):
            if _retries > 0:
                return llm_query(prompt, model, _retries=0)
            return f"Error: {d['error']}"
        resp = d.get("response", "")
        if not resp:
            if _retries > 0:
                return llm_query(prompt, model, _retries=0)
            return "Error: LLM returned empty response"
        return resp
    except Exception as e:
        if _retries > 0:
            return llm_query(prompt, model, _retries=0)
        return f"Error: LM query failed - {e}"


def llm_query_batched(prompts, model=None):
    """Query the LM with multiple prompts concurrently."""
    try:
        r = requests.post(
            f"{_PROXY}/llm_query_batched",
            json={"prompts": prompts, "model": model},
            timeout=300,
        )
        d = r.json()
        return (
            d.get("responses")
            or [f"Error: {d.get('error')}"] * len(prompts)
        )
    except Exception as e:
        return [f"Error: LM query failed - {e}"] * len(prompts)


# ── Tool wrappers ───────────────────────────────────────────────

def _make_tool_wrapper(name):
    def _wrapper(**kwargs):
        try:
            ser = {}
            for k, v in kwargs.items():
                if isinstance(v, (str, int, float, bool, type(None))):
                    ser[k] = v
                elif isinstance(v, (list, dict, tuple)):
                    ser[k] = json.loads(json.dumps(v, default=str))
                else:
                    ser[k] = str(v)
            r = requests.post(
                f"{_PROXY}/tool/{name}",
                json={"kwargs": ser},
                timeout=600,
            )
            d = r.json()
            if "error" in d:
                return f"Error: {d['error']}"
            return d.get("result", "")
        except Exception as e:
            return f"Error calling {name}: {e}"
    _wrapper.__name__ = name
    return _wrapper


# ── State persistence ───────────────────────────────────────────

def _load_state():
    if os.path.exists(_STATE):
        try:
            with open(_STATE, "rb") as f:
                return dill.load(f)
        except Exception:
            pass
    return {}


def _save_state(s):
    clean = {k: v for k, v in s.items() if not k.startswith("_")}
    for k in list(clean.keys()):
        try:
            dill.dumps(clean[k])
        except Exception:
            del clean[k]
    with open(_STATE, "wb") as f:
        dill.dump(clean, f)


# ── FINAL_VAR ───────────────────────────────────────────────────

_locals = _load_state()


def FINAL_VAR(variable_name):
    """Return the value of a variable as a final answer."""
    from json_repair import repair_json

    if not isinstance(variable_name, str):
        value = variable_name
    else:
        variable_name = variable_name.strip().strip("\"'")
        if variable_name in _locals:
            value = _locals[variable_name]
        else:
            # The model may have passed literal JSON instead
            # of a variable name — try to repair and parse it.
            trimmed = variable_name.strip()
            if trimmed.startswith(("{", "[")):
                try:
                    value = json.loads(repair_json(trimmed))
                except (json.JSONDecodeError, ValueError):
                    return (
                        f"Error: Variable '{variable_name}'"
                        " not found"
                    )
            else:
                return (
                    f"Error: Variable '{variable_name}'"
                    " not found"
                )
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


# ── Build namespace and execute ─────────────────────────────────

_globals = {
    "__builtins__": __builtins__,
    "__name__": "__main__",
    "llm_query": llm_query,
    "llm_query_batched": llm_query_batched,
    "FINAL_VAR": FINAL_VAR,
}

for _tn in _params.get("tool_names", []):
    _globals[_tn] = _make_tool_wrapper(_tn)

_body = (
    base64.b64decode(_params["body_b64"]).decode()
    if _params.get("body_b64")
    else ""
)
_last_expr = (
    base64.b64decode(_params["last_expr_b64"]).decode()
    if _params.get("last_expr_b64")
    else None
)
_targets = set(_params.get("targets", []))

_stdout_buf = io.StringIO()
_stderr_buf = io.StringIO()
_old_stdout, _old_stderr = sys.stdout, sys.stderr

_combined = {**_globals, **_locals}
_error_msg = None

try:
    sys.stdout, sys.stderr = _stdout_buf, _stderr_buf
    if _body:
        exec(_body, _combined, _combined)
    if _last_expr is not None:
        _eval_result = eval(_last_expr, _combined, _combined)
        if _eval_result is not None:
            print(repr(_eval_result))
except Exception as _e:
    _error_msg = f"[error] {type(_e).__name__}: {_e}"
    _stderr_buf.write(f"\n{_error_msg}")
finally:
    sys.stdout, sys.stderr = _old_stdout, _old_stderr

if _error_msg:
    for _tname in _targets:
        if _tname not in _combined:
            _combined[_tname] = _error_msg

for _k, _v in _combined.items():
    if _k not in _globals and not _k.startswith("_"):
        _locals[_k] = _v

_save_state(_locals)

print(json.dumps({
    "stdout": _stdout_buf.getvalue(),
    "stderr": _stderr_buf.getvalue(),
    "locals": {
        k: repr(v)
        for k, v in _locals.items()
        if not k.startswith("_")
    },
}, ensure_ascii=False))
'''


# =============================================================================
# LLM Proxy Handler
# =============================================================================


class LLMProxyHandler(BaseHTTPRequestHandler):
    """HTTP proxy for LLM and tool requests from the container."""

    lm_handler_address: tuple[str, int] | None = None
    pending_calls: list[RLMChatCompletion] = []
    tools: dict[str, Any] = {}
    lock: threading.Lock = threading.Lock()
    depth: int = 1
    query_model: str | None = None

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(length))

        if self.path == "/llm_query":
            result = self._handle_single(body)
        elif self.path == "/llm_query_batched":
            result = self._handle_batched(body)
        elif self.path.startswith("/tool/"):
            result = self._handle_tool(self.path[6:], body)
        else:
            self._respond(404, {"error": "Not found"})
            return

        self._respond(200, result)

    def _respond(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _handle_single(self, body: dict) -> dict:
        if self.lm_handler_address is None:
            return {"error": "No LM handler configured"}

        model = body.get("model") or self.query_model
        request = LMRequest(
            prompt=body.get("prompt"),
            model=model,
            depth=self.depth,
        )
        response = send_lm_request(self.lm_handler_address, request)

        if not response.success:
            return {"error": response.error}

        assert response.chat_completion is not None
        with self.lock:
            self.pending_calls.append(response.chat_completion)

        return {"response": response.chat_completion.response}

    def _handle_batched(self, body: dict) -> dict:
        if self.lm_handler_address is None:
            return {"error": "No LM handler configured"}

        prompts = body.get("prompts", [])
        responses = send_lm_request_batched(
            self.lm_handler_address,
            prompts,
            model=body.get("model"),
            depth=self.depth,
        )

        results = []
        for resp in responses:
            if not resp.success:
                results.append(f"Error: {resp.error}")
            else:
                assert resp.chat_completion is not None
                with self.lock:
                    self.pending_calls.append(resp.chat_completion)
                results.append(resp.chat_completion.response)

        return {"responses": results}

    def _handle_tool(self, tool_name: str, body: dict) -> dict:
        fn = self.tools.get(tool_name)
        if fn is None:
            return {"error": f"Tool '{tool_name}' not found"}

        kwargs = body.get("kwargs", {})
        try:
            result = fn(**kwargs)
            if result is None:
                return {"result": ""}
            return {"result": str(result)}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}


# =============================================================================
# DockerREPL
# =============================================================================


class DockerREPL(NonIsolatedEnv):
    """Docker REPL — runs Python in a Docker container with LLM support.

    Requires: Docker with a Python 3.11+ image
    (default: python:3.11-slim).
    """

    _exec_timeout: int = int(os.environ.get("KAI_EXEC_TIMEOUT", 1200))

    def __init__(
        self,
        image: str = "python:3.11-slim",
        lm_handler_address: tuple[str, int] | None = None,
        context_payload: dict | list | str | None = None,
        setup_code: str | None = None,
        persistent: bool = False,
        depth: int = 1,
        tools: dict[str, Any] | None = None,
        **kwargs,
    ):
        if persistent:
            raise NotImplementedError(
                "Persistent REPLs are currently not "
                "supported for environment: DockerREPL"
            )
        factory = kwargs.pop("workspace_factory", None)
        self._query_model: str | None = kwargs.pop("query_model", None)
        super().__init__(persistent=persistent, depth=depth, **kwargs)

        self.image = image
        self.lm_handler_address = lm_handler_address
        self.container_id: str | None = None
        self.proxy_server: HTTPServer | None = None
        self.proxy_thread: threading.Thread | None = None
        self.proxy_port: int = 0
        self._context_count: int = 0
        self._history_count: int = 0
        self._tools: dict[str, Any] = tools or {}

        if factory is not None:
            self.temp_dir = factory()
        else:
            base_dir = os.environ.get(
                "RLM_DOCKER_WORKSPACE_DIR",
                os.path.join(os.getcwd(), ".rlm_workspace"),
            )
            os.makedirs(base_dir, exist_ok=True)
            self.temp_dir = tempfile.mkdtemp(prefix="docker_repl_", dir=base_dir)

        self.pending_calls: list[RLMChatCompletion] = []
        self._calls_lock = threading.Lock()
        self._handler_cls: type | None = None

        self.setup()

        if context_payload is not None:
            self.load_context(context_payload)
        if setup_code:
            self.execute_code(setup_code)

    def setup(self):
        """Start the proxy server and Docker container."""
        handler_cls = type(
            "Handler",
            (LLMProxyHandler,),
            {
                "lm_handler_address": self.lm_handler_address,
                "pending_calls": self.pending_calls,
                "tools": self._tools,
                "lock": self._calls_lock,
                "depth": self.depth,
                "query_model": self._query_model,
            },
        )
        self._handler_cls = handler_cls

        self.proxy_server = HTTPServer(("127.0.0.1", 0), handler_cls)
        self.proxy_port = self.proxy_server.server_address[1]
        self.proxy_thread = threading.Thread(
            target=self.proxy_server.serve_forever, daemon=True
        )
        self.proxy_thread.start()

        # Write the executor script to the mounted workspace
        executor_path = os.path.join(self.temp_dir, "_executor.py")
        with open(executor_path, "w") as f:
            f.write(_EXECUTOR_SCRIPT)

        # Start Docker container
        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "-v",
                f"{self.temp_dir}:/workspace",
                "--add-host",
                "host.docker.internal:host-gateway",
                self.image,
                "tail",
                "-f",
                "/dev/null",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to start container: {result.stderr}")

        self.container_id = result.stdout.strip()

        # Install dependencies
        assert self.container_id is not None
        subprocess.run(
            [
                "docker",
                "exec",
                self.container_id,
                "pip",
                "install",
                "-q",
                "dill",
                "requests",
            ],
            capture_output=True,
        )

    # =================================================================
    # SupportsPersistence protocol
    # =================================================================

    def update_handler_address(self, address: tuple[str, int]) -> None:
        """Update the LM handler address for a new completion."""
        self.lm_handler_address = address
        if self._handler_cls is not None:
            self._handler_cls.lm_handler_address = address  # type: ignore[attr-defined]

    def load_context(self, context_payload: dict | list | str):
        """Load context as context_0 (and ``context`` alias)."""
        self.add_context(context_payload, 0)

    def add_context(
        self,
        context_payload: dict | list | str,
        context_index: int | None = None,
    ) -> int:
        """Add a versioned context variable (``context_N``)."""
        if context_index is None:
            context_index = self._context_count

        var_name = f"context_{context_index}"

        if isinstance(context_payload, str):
            fname = f"context_{context_index}.txt"
            path = os.path.join(self.temp_dir, fname)
            with open(path, "w") as f:
                f.write(context_payload)
            self.execute_code(
                f"with open('/workspace/{fname}', 'r') as f:\n    {var_name} = f.read()"
            )
        else:
            fname = f"context_{context_index}.json"
            path = os.path.join(self.temp_dir, fname)
            with open(path, "w") as f:
                json.dump(context_payload, f)
            self.execute_code(
                f"import json\nwith open("
                f"'/workspace/{fname}', 'r') "
                f"as f:\n    {var_name} = json.load(f)"
            )

        if context_index == 0:
            self.execute_code(f"context = {var_name}")

        self._context_count = max(self._context_count, context_index + 1)
        return context_index

    def get_context_count(self) -> int:
        """Return the number of contexts loaded."""
        return self._context_count

    def add_history(
        self,
        message_history: list[dict[str, Any]],
        history_index: int | None = None,
    ) -> int:
        """Store a conversation history as ``history_N``."""
        if history_index is None:
            history_index = self._history_count

        var_name = f"history_{history_index}"

        fname = f"history_{history_index}.json"
        path = os.path.join(self.temp_dir, fname)
        with open(path, "w") as f:
            json.dump(copy.deepcopy(message_history), f)

        self.execute_code(
            f"import json\nwith open("
            f"'/workspace/{fname}', 'r') "
            f"as f:\n    {var_name} = json.load(f)"
        )

        if history_index == 0:
            self.execute_code(f"history = {var_name}")

        self._history_count = max(self._history_count, history_index + 1)
        return history_index

    def get_history_count(self) -> int:
        """Return the number of conversation histories stored."""
        return self._history_count

    # =================================================================
    # Code analysis helpers (same as LocalREPL)
    # =================================================================

    @staticmethod
    def _split_last_expr(
        code: str,
    ) -> tuple[str, str | None]:
        """Split code into body + trailing expression (if any).

        If the last statement is a bare expression its return
        value is auto-printed — like interactive Python.
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

    @staticmethod
    def _find_assignment_targets(code: str) -> set[str]:
        """Return simple Name targets from all assignments.

        Handles plain assignments, annotated assignments, and
        tuple/list unpacking.
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

    # =================================================================
    # Execution
    # =================================================================

    def execute_code(self, code: str) -> REPLResult:
        """Execute code in the Docker container.

        Mirrors LocalREPL behaviour: auto-prints trailing
        expressions, preserves variables on error/timeout, and
        collects spawn records from tools.
        """
        start = time.perf_counter()

        with self._calls_lock:
            self.pending_calls.clear()

        # Cooperative cancellation for host-side tools
        cancel_event = threading.Event()
        for fn in self._tools.values():
            try:
                fn._cancel_event = cancel_event
            except AttributeError:
                pass

        # AST analysis on the host side
        body, last_expr = self._split_last_expr(code)
        targets = self._find_assignment_targets(code)

        # Write execution parameters to the mounted workspace
        params: dict[str, Any] = {
            "proxy_port": self.proxy_port,
            "query_model": self._query_model,
            "tool_names": list(self._tools.keys()),
            "targets": list(targets),
        }
        if body:
            params["body_b64"] = base64.b64encode(body.encode()).decode()
        if last_expr is not None:
            params["last_expr_b64"] = base64.b64encode(last_expr.encode()).decode()

        params_path = os.path.join(self.temp_dir, "_exec_params.json")
        with open(params_path, "w") as f:
            json.dump(params, f)

        assert self.container_id is not None

        timed_out = False
        try:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    self.container_id,
                    "python",
                    "/workspace/_executor.py",
                ],
                capture_output=True,
                text=True,
                timeout=self._exec_timeout,
            )
            stdout_raw = result.stdout
            stderr_raw = result.stderr
        except subprocess.TimeoutExpired as exc:
            cancel_event.set()
            stdout_raw = (exc.stdout or b"").decode(errors="replace")
            stderr_raw = (exc.stderr or b"").decode(errors="replace")
            timed_out = True

        # Collect LLM calls that came through the proxy
        with self._calls_lock:
            calls = self.pending_calls.copy()
            self.pending_calls.clear()

        # Drain sub-agent completions and spawn records
        spawn_records: list[SpawnRecord] = []
        for fn in self._tools.values():
            pending = getattr(fn, "_pending_completions", None)
            if pending:
                calls.extend(pending)
                pending.clear()
            records = getattr(fn, "_spawn_records", None)
            if records:
                spawn_records.extend(records)
                records.clear()

        elapsed = time.perf_counter() - start

        if timed_out:
            error_msg = (
                f"[error] TimeoutError: execution exceeded {self._exec_timeout}s limit"
            )
            return REPLResult(
                stdout=stdout_raw,
                stderr=stderr_raw + f"\n{error_msg}",
                locals={},
                execution_time=elapsed,
                rlm_calls=calls,
                spawn_records=spawn_records,
            )

        try:
            lines = stdout_raw.strip().split("\n")
            data = json.loads(lines[-1]) if lines else {}
            return REPLResult(
                stdout=data.get("stdout", ""),
                stderr=data.get("stderr", "") + stderr_raw,
                locals=data.get("locals", {}),
                execution_time=elapsed,
                rlm_calls=calls,
                spawn_records=spawn_records,
            )
        except json.JSONDecodeError:
            return REPLResult(
                stdout=stdout_raw,
                stderr=stderr_raw or "Parse error",
                locals={},
                execution_time=elapsed,
                rlm_calls=calls,
                spawn_records=spawn_records,
            )

    # =================================================================
    # Lifecycle
    # =================================================================

    def cleanup(self):
        """Stop container and proxy, remove workspace."""
        if hasattr(self, "container_id") and self.container_id:
            subprocess.run(
                ["docker", "stop", self.container_id],
                capture_output=True,
            )
            self.container_id = None
        if hasattr(self, "proxy_server") and self.proxy_server:
            self.proxy_server.shutdown()
            self.proxy_server = None
        if hasattr(self, "temp_dir") and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()
        return False

    def __del__(self):
        self.cleanup()
