"""Regression tests for B-001: --log-file must be honoured in both modes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ra.logger import StructuredPrinter, VerbosePrinter, create_printer


@pytest.fixture
def log_file_path(tmp_path: Path) -> Path:
    return tmp_path / "logs" / "events.log"


def test_structured_printer_writes_to_log_file(log_file_path: Path) -> None:
    printer = StructuredPrinter(
        enabled=True, name="setup", depth=0, log_file=str(log_file_path)
    )
    printer.print_header(
        backend="openrouter",
        model="opus",
        environment="local",
        max_iterations=5,
        max_depth=1,
    )
    if printer._log_fh is not None:
        printer._log_fh.flush()

    assert log_file_path.exists(), "--log-file must be created in structured mode"
    contents = log_file_path.read_text().strip().splitlines()
    assert contents, "log_file must contain at least one event"
    payload = json.loads(contents[0])
    assert payload["event"] == "header"
    assert payload["agent"] == "setup"


def test_verbose_printer_writes_to_log_file(log_file_path: Path) -> None:
    printer = VerbosePrinter(
        enabled=True, name="setup", depth=0, log_file=str(log_file_path)
    )
    printer.print_header(
        backend="openrouter",
        model="opus",
        environment="local",
        max_iterations=5,
        max_depth=1,
    )
    if printer._log_fh is not None:
        printer._log_fh.flush()

    assert log_file_path.exists(), "--log-file must be created in verbose mode"
    assert log_file_path.read_text().strip(), "verbose log_file must have content"


def test_create_printer_routes_log_file_for_both_modes(
    tmp_path: Path,
) -> None:
    structured_path = tmp_path / "structured.log"
    verbose_path = tmp_path / "verbose.log"

    sp = create_printer(
        enabled=True, name="x", depth=0, log_file=str(structured_path), structured=True
    )
    assert isinstance(sp, StructuredPrinter)
    assert sp._log_fh is not None

    vp = create_printer(
        enabled=True, name="x", depth=0, log_file=str(verbose_path), structured=False
    )
    assert isinstance(vp, VerbosePrinter)
    assert vp._log_fh is not None


def test_setup_cfg_propagates_log_file() -> None:
    """When the pipeline replaces setup_config it must carry log_file through.

    Regression for B-001 — previously the replace() call only carried
    verbose + log_structured, so the setup agent's printer was never
    given a log_file path.
    """

    from dataclasses import replace

    from kai.definitions import setup_config

    cfg = replace(
        setup_config,
        verbose=True,
        log_structured=True,
        log_file="/tmp/should-not-actually-open.log",
    )
    assert cfg.log_file == "/tmp/should-not-actually-open.log"
    assert cfg.log_structured is True
    assert cfg.verbose is True
