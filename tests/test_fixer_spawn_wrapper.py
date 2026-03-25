"""Tests for make_fixer_spawn_wrapper and _run_poc_precheck."""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

from kai.definitions.exploit.spawn_hooks import (
    _run_poc_precheck,
    make_fixer_spawn_wrapper,
)
from kai.workspace.recipe import WorkspaceRecipe


def _make_recipe(master_path: str) -> WorkspaceRecipe:
    """Build a minimal recipe pointing at *master_path*."""
    return WorkspaceRecipe(
        master_path=master_path,
        symlink_dirs=[],
        copy_dirs=[],
        copy_files=[],
        post_copy_commands=[],
    )


def _echo_spawn(**kwargs: object) -> str:
    """Fake spawn function that returns kwargs as JSON."""
    return json.dumps(kwargs, default=str)


def _make_state_manager() -> MagicMock:
    sm = MagicMock()
    sm.get_fix_attempts.return_value = []
    return sm


class TestRunPocPrecheck:
    """Test _run_poc_precheck provisions workspace and runs PoC."""

    def test_poc_fails_means_already_patched(self) -> None:
        """If PoC exits non-zero on clean workspace, report patched."""
        master = tempfile.mkdtemp()
        recipe = _make_recipe(master)
        # PoC that always exits 1 (exploit blocked)
        poc = "import sys; sys.exit(1)"
        assert _run_poc_precheck(recipe, poc) is True

    def test_poc_succeeds_means_not_patched(self) -> None:
        """If PoC exits 0 on clean workspace, report still vulnerable."""
        master = tempfile.mkdtemp()
        recipe = _make_recipe(master)
        # PoC that always exits 0 (exploit triggers)
        poc = "import sys; sys.exit(0)"
        assert _run_poc_precheck(recipe, poc) is False

    def test_timeout_assumes_not_patched(self) -> None:
        """If PoC times out, assume still vulnerable."""
        master = tempfile.mkdtemp()
        recipe = _make_recipe(master)
        poc = "import time; time.sleep(999)"
        # Very short timeout to trigger TimeoutExpired
        assert _run_poc_precheck(recipe, poc, timeout=1) is False

    def test_provisioning_failure_assumes_not_patched(self) -> None:
        """If workspace provisioning fails, assume still vulnerable."""
        recipe = _make_recipe("/nonexistent/path")
        with patch(
            "kai.workspace.provisioner.provision_workspace",
            side_effect=OSError("boom"),
        ):
            assert _run_poc_precheck(recipe, "print('hi')") is False

    def test_detects_solidity_poc(self) -> None:
        """PoC with 'pragma solidity' gets .t.sol extension."""
        master = tempfile.mkdtemp()
        recipe = _make_recipe(master)
        poc = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;"
        # Will fail because forge isn't installed, but we just want
        # to verify it doesn't crash and returns False (not patched)
        result = _run_poc_precheck(recipe, poc)
        assert result is False  # forge not found → non-zero, but exception path

    def test_workspace_cleaned_up(self) -> None:
        """Workspace should be removed after pre-check."""
        master = tempfile.mkdtemp()
        recipe = _make_recipe(master)
        provisioned_dirs: list[str] = []

        _real_provision = None
        from kai.workspace.provisioner import (
            provision_workspace as _real_fn,
        )

        _real_provision = _real_fn

        def tracking_provision(r: WorkspaceRecipe) -> str:
            ws = _real_provision(r)
            provisioned_dirs.append(ws)
            return ws

        with patch(
            "kai.workspace.provisioner.provision_workspace",
            side_effect=tracking_provision,
        ):
            _run_poc_precheck(recipe, "import sys; sys.exit(0)")

        assert len(provisioned_dirs) == 1
        assert not os.path.exists(provisioned_dirs[0])


class TestMakeFixerSpawnWrapper:
    """Test make_fixer_spawn_wrapper with and without recipe."""

    def test_injects_prior_fix_attempts(self) -> None:
        sm = _make_state_manager()
        attempt = MagicMock()
        attempt.strategy = "input validation"
        attempt.patch = "diff..."
        attempt.failure_reason = "bypass found"
        attempt.succeeded = False
        sm.get_fix_attempts.return_value = [attempt]

        wrapped = make_fixer_spawn_wrapper(_echo_spawn, sm, "r1")
        result = json.loads(
            wrapped(
                exploit_id="e1",
                hypothesis="h",
                file="f",
                function="fn",
                poc_code="poc",
            )
        )
        assert "prior_fix_attempts" in result
        assert len(result["prior_fix_attempts"]) == 1
        assert result["prior_fix_attempts"][0]["strategy"] == "input validation"

    def test_no_prior_attempts_skips_injection(self) -> None:
        sm = _make_state_manager()
        wrapped = make_fixer_spawn_wrapper(_echo_spawn, sm, "r1")
        result = json.loads(
            wrapped(exploit_id="e1", hypothesis="h", poc_code="poc")
        )
        assert "prior_fix_attempts" not in result

    def test_precheck_skips_fixer_when_patched(self) -> None:
        """When PoC already fails, wrapper returns synthetic result."""
        sm = _make_state_manager()
        master = tempfile.mkdtemp()
        recipe = _make_recipe(master)

        # PoC that always fails → already patched
        poc = "import sys; sys.exit(1)"
        spawn_called = []

        def tracking_spawn(**kwargs: object) -> str:
            spawn_called.append(True)
            return "{}"

        wrapped = make_fixer_spawn_wrapper(
            tracking_spawn, sm, "r1", recipe=recipe
        )
        raw = wrapped(
            exploit_id="e1",
            hypothesis="test vuln",
            file="f.sol",
            function="fn",
            poc_code=poc,
        )
        result = json.loads(raw)
        assert result["fix_succeeded"] is False
        assert result["failure_reason"] == "vulnerability_already_patched"
        assert result["hypothesis"] == "test vuln"
        # Original spawn should NOT have been called
        assert spawn_called == []

    def test_precheck_proceeds_when_not_patched(self) -> None:
        """When PoC succeeds (exit 0), fixer agent is spawned."""
        sm = _make_state_manager()
        master = tempfile.mkdtemp()
        recipe = _make_recipe(master)

        poc = "import sys; sys.exit(0)"  # exploit still triggers

        wrapped = make_fixer_spawn_wrapper(
            _echo_spawn, sm, "r1", recipe=recipe
        )
        raw = wrapped(
            exploit_id="e1",
            hypothesis="h",
            file="f",
            function="fn",
            poc_code=poc,
        )
        result = json.loads(raw)
        # Should have called through to the actual spawn
        assert result["hypothesis"] == "h"
        assert "failure_reason" not in result

    def test_no_recipe_skips_precheck(self) -> None:
        """Without recipe, wrapper skips pre-check entirely."""
        sm = _make_state_manager()
        wrapped = make_fixer_spawn_wrapper(_echo_spawn, sm, "r1")
        raw = wrapped(
            exploit_id="e1",
            hypothesis="h",
            file="f",
            function="fn",
            poc_code="import sys; sys.exit(1)",  # would be "patched"
        )
        result = json.loads(raw)
        # Without recipe, pre-check is skipped → spawn proceeds
        assert result["hypothesis"] == "h"
        assert "failure_reason" not in result

    def test_no_poc_code_skips_precheck(self) -> None:
        """Without poc_code in kwargs, pre-check is skipped."""
        sm = _make_state_manager()
        master = tempfile.mkdtemp()
        recipe = _make_recipe(master)
        wrapped = make_fixer_spawn_wrapper(
            _echo_spawn, sm, "r1", recipe=recipe
        )
        raw = wrapped(exploit_id="e1", hypothesis="h")
        result = json.loads(raw)
        assert result["hypothesis"] == "h"
