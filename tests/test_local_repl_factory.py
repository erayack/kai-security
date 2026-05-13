"""Tests for LocalREPL workspace_factory and auto-print support."""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from ra.environments import get_environment
from ra.environments.local_repl import LocalREPL


class TestLocalREPLDefaultTempDir:
    def test_creates_temp_dir(self) -> None:
        repl = LocalREPL()
        try:
            assert os.path.isdir(repl.temp_dir)
            assert "repl_env_" in repl.temp_dir
        finally:
            repl.cleanup()

    def test_cleanup_removes_temp_dir(self) -> None:
        repl = LocalREPL()
        path = repl.temp_dir
        repl.cleanup()
        assert not os.path.exists(path)


class TestEnvironmentFactory:
    def test_local_environment_supported(self) -> None:
        env = get_environment("local", {})
        try:
            assert isinstance(env, LocalREPL)
        finally:
            env.cleanup()

    def test_unknown_environment_not_supported(self) -> None:
        with pytest.raises(ValueError, match=r"Supported: \['local', 'docker'\]"):
            get_environment("remote", {})


class TestLocalREPLWorkspaceFactory:
    def test_factory_sets_temp_dir(self) -> None:
        custom_dir = tempfile.mkdtemp(prefix="test_factory_")
        try:
            repl = LocalREPL(workspace_factory=lambda: custom_dir)
            assert repl.temp_dir == custom_dir
            repl.cleanup()
        finally:
            # cleanup may have already removed it
            shutil.rmtree(custom_dir, ignore_errors=True)

    def test_factory_dir_used_for_execution(self) -> None:
        custom_dir = tempfile.mkdtemp(prefix="test_exec_")
        try:
            repl = LocalREPL(workspace_factory=lambda: custom_dir)
            # Code execution should use the factory-provided dir
            repl.execute_code("import os; cwd = os.getcwd()")
            # Resolve both to handle macOS /var -> /private/var symlink
            assert os.path.realpath(str(repl.locals.get("cwd"))) == (
                os.path.realpath(custom_dir)
            )
            repl.cleanup()
        finally:
            shutil.rmtree(custom_dir, ignore_errors=True)

    def test_factory_with_files(self, tmp_path: Path) -> None:
        """Factory-provided workspace with pre-existing files."""
        (tmp_path / "data.txt").write_text("hello")

        repl = LocalREPL(workspace_factory=lambda: str(tmp_path))
        repl.execute_code("with open('data.txt') as f: content = f.read()")
        assert repl.locals.get("content") == "hello"
        repl.cleanup()

    def test_none_factory_uses_default(self) -> None:
        """Passing workspace_factory=None uses default mkdtemp."""
        repl = LocalREPL(workspace_factory=None)
        try:
            assert os.path.isdir(repl.temp_dir)
            assert "repl_env_" in repl.temp_dir
        finally:
            repl.cleanup()

    def test_factory_kwarg_not_passed_to_parent(self) -> None:
        """workspace_factory should be popped, not passed to super()."""
        # If it wasn't popped, super().__init__ would get an unexpected
        # kwarg and raise TypeError. This test just verifies no error.
        repl = LocalREPL(workspace_factory=lambda: tempfile.mkdtemp())
        path = repl.temp_dir
        repl.cleanup()
        shutil.rmtree(path, ignore_errors=True)


# ── _split_last_expr ─────────────────────────────────────────────


class TestSplitLastExpr:
    def test_bare_function_call(self) -> None:
        body, expr = LocalREPL._split_last_expr('foo("bar")')
        assert body == ""
        assert expr == 'foo("bar")'

    def test_trailing_expr_after_statement(self) -> None:
        body, expr = LocalREPL._split_last_expr("x = 1\nx + 2")
        assert body == "x = 1\n"
        assert expr == "x + 2"

    def test_assignment_not_split(self) -> None:
        body, expr = LocalREPL._split_last_expr("x = foo()")
        assert expr is None

    def test_for_loop_not_split(self) -> None:
        code = "for i in range(3):\n    print(i)"
        _, expr = LocalREPL._split_last_expr(code)
        assert expr is None

    def test_syntax_error_returns_none(self) -> None:
        _, expr = LocalREPL._split_last_expr("def foo(")
        assert expr is None

    def test_empty_code(self) -> None:
        _, expr = LocalREPL._split_last_expr("")
        assert expr is None

    def test_multiline_expr(self) -> None:
        code = "x = 1\nfoo(\n    x\n)"
        body, expr = LocalREPL._split_last_expr(code)
        assert body == "x = 1\n"
        assert expr is not None and "foo(" in expr


# ── Auto-print in execute_code ───────────────────────────────────


class TestAutoprint:
    @pytest.fixture()
    def repl(self) -> Generator[LocalREPL, None, None]:
        r = LocalREPL()
        yield r
        r.cleanup()

    def test_bare_expr_printed(self, repl: LocalREPL) -> None:
        result = repl.execute_code("1 + 2")
        assert "3" in result.stdout

    def test_bare_function_call_printed(self, repl: LocalREPL) -> None:
        result = repl.execute_code("len([1, 2, 3])")
        assert "3" in result.stdout

    def test_assignment_not_printed(self, repl: LocalREPL) -> None:
        result = repl.execute_code("x = 10")
        assert result.stdout.strip() == ""

    def test_print_not_duplicated(self, repl: LocalREPL) -> None:
        result = repl.execute_code("print(42)")
        lines = [ln for ln in result.stdout.strip().splitlines() if ln]
        assert lines == ["42"]

    def test_none_result_not_printed(self, repl: LocalREPL) -> None:
        result = repl.execute_code("print('hi')")
        assert "None" not in result.stdout

    def test_print_plus_trailing_expr(self, repl: LocalREPL) -> None:
        result = repl.execute_code('print("first")\n42')
        assert "first" in result.stdout
        assert "42" in result.stdout

    def test_tool_return_value_visible(self, repl: LocalREPL) -> None:
        """Simulates the researcher bug: tool called without print()."""
        repl.execute_code('def search_web(q): return f"results for {q}"')
        result = repl.execute_code('search_web("CVE-2024")')
        assert "results for CVE-2024" in result.stdout

    def test_locals_still_updated(self, repl: LocalREPL) -> None:
        repl.execute_code("x = [1, 2, 3]\nlen(x)")
        assert repl.locals.get("x") == [1, 2, 3]

    def test_no_double_exec_assignment_ending(self, repl: LocalREPL) -> None:
        """Code ending with an assignment must run exactly once."""
        code = "items = []\nitems.append(1)\nprint(len(items))\nx = 42"
        result = repl.execute_code(code)
        assert result.stdout.strip() == "1"
        assert repl.locals["items"] == [1]

    def test_no_double_exec_for_loop_ending(self, repl: LocalREPL) -> None:
        """Code ending with a for loop must run exactly once."""
        code = "nums = []\nfor i in range(3):\n    nums.append(i)"
        repl.execute_code(code)
        assert repl.locals["nums"] == [0, 1, 2]

    def test_no_double_exec_if_ending(self, repl: LocalREPL) -> None:
        """Code ending with an if statement must run exactly once."""
        code = "counter = [0]\nif True:\n    counter[0] += 1"
        repl.execute_code(code)
        assert repl.locals["counter"] == [1]

    def test_timeout_kills_long_running_code(self, repl: LocalREPL) -> None:
        """Code exceeding _exec_timeout returns a TimeoutError."""
        repl._exec_timeout = 1  # 1 second for testing
        code = "import time\ntime.sleep(10)"
        result = repl.execute_code(code)
        assert "TimeoutError" in result.stderr
        assert "1s limit" in result.stderr

    def test_timeout_assigns_error_to_target(self, repl: LocalREPL) -> None:
        """On timeout, the assignment target gets the error string."""
        repl._exec_timeout = 1
        code = "import time\ndef slow(): time.sleep(10); return 1\nx = slow()"
        repl.execute_code(code)
        assert isinstance(repl.locals.get("x"), str)
        assert "[error]" in repl.locals["x"]
        assert "TimeoutError" in repl.locals["x"]

    def test_error_assigns_error_to_target(self, repl: LocalREPL) -> None:
        """On exception, the assignment target gets the error string."""
        code = "y = 1 / 0"
        repl.execute_code(code)
        assert isinstance(repl.locals.get("y"), str)
        assert "[error]" in repl.locals["y"]
        assert "ZeroDivisionError" in repl.locals["y"]

    def test_error_preserves_earlier_assignments(self, repl: LocalREPL) -> None:
        """Variables assigned before the error survive."""
        code = "a = 42\nb = 1 / 0"
        repl.execute_code(code)
        assert repl.locals.get("a") == 42
        assert isinstance(repl.locals.get("b"), str)
        assert "[error]" in repl.locals["b"]

    def test_tuple_unpack_targets_get_error(self, repl: LocalREPL) -> None:
        """Tuple unpacking targets get the error on failure."""
        code = "p, q = 1 / 0"
        repl.execute_code(code)
        assert isinstance(repl.locals.get("p"), str)
        assert "[error]" in repl.locals["p"]
        assert isinstance(repl.locals.get("q"), str)
        assert "[error]" in repl.locals["q"]

    def test_error_var_usable_next_iteration(self, repl: LocalREPL) -> None:
        """Error-assigned variable is accessible in the next exec."""
        repl.execute_code("x = 1 / 0")
        result = repl.execute_code("print(x)")
        assert "[error]" in result.stdout
