"""Local JSON-file-based state manager."""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from kai.state.base import StateManager
from kai.state.models import (
    ExploitRecord,
    FixRecord,
    RunRecord,
    StatusUpdate,
)

log = logging.getLogger(__name__)

_DEFAULT_SUMMARY_MODEL = "openai/gpt-4o-mini"


class LocalStateManager(StateManager):
    """StateManager backed by local JSON files.

    Storage layout::

        <state_dir>/<run_id>/
            run.json              # Single RunRecord
            status_updates.jsonl  # Append-only, one StatusUpdate per line
            exploits.json         # JSON array of ExploitRecord
            fixes.json            # JSON array of FixRecord

    All reads go through disk — no in-memory cache.  This keeps the
    implementation simple and crash-resilient.  Thread-safe via a
    ``threading.Lock``.
    """

    def __init__(
        self,
        state_dir: str = "output/state",
        summary_backend: str = "openrouter",
        summary_model: str | None = None,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._summary_backend = summary_backend
        self._summary_model = summary_model or os.environ.get(
            "KAI_SUMMARY_MODEL", _DEFAULT_SUMMARY_MODEL
        )
        self._lock = threading.Lock()

    # -- helpers --

    def _run_dir(self, run_id: str) -> Path:
        d = self._state_dir / run_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _write_json(self, path: Path, data: Any) -> None:
        path.write_text(json.dumps(data, indent=2))

    def _read_json(self, path: Path) -> Any:
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def _read_exploits(self, run_id: str) -> list[ExploitRecord]:
        path = self._run_dir(run_id) / "exploits.json"
        data = self._read_json(path)
        return [ExploitRecord.from_dict(d) for d in data] if data else []

    def _write_exploits(self, run_id: str, records: list[ExploitRecord]) -> None:
        path = self._run_dir(run_id) / "exploits.json"
        self._write_json(path, [e.to_dict() for e in records])

    def _read_fixes(self, run_id: str) -> list[FixRecord]:
        path = self._run_dir(run_id) / "fixes.json"
        data = self._read_json(path)
        return [FixRecord.from_dict(d) for d in data] if data else []

    def _write_fixes(self, run_id: str, records: list[FixRecord]) -> None:
        path = self._run_dir(run_id) / "fixes.json"
        self._write_json(path, [f.to_dict() for f in records])

    # -- Run lifecycle --

    def create_run(self, record: RunRecord) -> None:
        """Persist a new run record."""
        try:
            with self._lock:
                path = self._run_dir(record.run_id) / "run.json"
                self._write_json(path, record.to_dict())
        except Exception:
            log.exception("create_run failed for %s", record.run_id)

    def update_run(self, run_id: str, **fields: object) -> None:
        """Update fields on an existing run record."""
        try:
            with self._lock:
                path = self._run_dir(run_id) / "run.json"
                data = self._read_json(path)
                if data is None:
                    log.warning("update_run: run %s not found", run_id)
                    return
                data.update(fields)
                self._write_json(path, data)
        except Exception:
            log.exception("update_run failed for %s", run_id)

    def get_run(self, run_id: str) -> RunRecord | None:
        """Return the run record, or ``None`` if not found."""
        try:
            with self._lock:
                path = self._run_dir(run_id) / "run.json"
                data = self._read_json(path)
                if data is None:
                    return None
                return RunRecord.from_dict(data)
        except Exception:
            log.exception("get_run failed for %s", run_id)
            return None

    # -- Progress tracking --

    def add_status_update(self, update: StatusUpdate) -> None:
        """Append a status update (one JSON line)."""
        try:
            with self._lock:
                path = self._run_dir(update.run_id) / "status_updates.jsonl"
                with open(path, "a") as f:
                    f.write(json.dumps(update.to_dict()) + "\n")
        except Exception:
            log.exception("add_status_update failed for run %s", update.run_id)

    @staticmethod
    def _tail_lines(path: Path, n: int) -> list[str]:
        """Read the last *n* lines from a file without loading it all."""
        with open(path, "rb") as f:
            f.seek(0, 2)  # end of file
            size = f.tell()
            if size == 0:
                return []
            buf = bytearray()
            pos = size
            lines_found = 0
            while pos > 0 and lines_found <= n:
                chunk = min(4096, pos)
                pos -= chunk
                f.seek(pos)
                buf[0:0] = f.read(chunk)
                lines_found = buf.count(b"\n")
            decoded = buf.decode("utf-8", errors="replace").splitlines()
            return decoded[-n:]

    def get_status_updates(
        self,
        run_id: str,
        last_n: int = 1,
    ) -> list[StatusUpdate]:
        """Return status updates for a run.

        Args:
            run_id: The run to query.
            last_n: Only deserialize and return the last *n* lines.
                Reads from the tail of the file to avoid loading the
                full history into memory.
        """
        try:
            with self._lock:
                path = self._run_dir(run_id) / "status_updates.jsonl"
                if not path.exists():
                    return []
                lines = self._tail_lines(path, last_n)
                updates: list[StatusUpdate] = []
                for raw in lines:
                    raw = raw.strip()
                    if raw:
                        updates.append(StatusUpdate.from_dict(json.loads(raw)))
                return updates
        except Exception:
            log.exception("get_status_updates failed for %s", run_id)
            return []

    # -- Exploits --

    def add_exploit(self, exploit: ExploitRecord) -> None:
        """Persist a new exploit record."""
        try:
            with self._lock:
                records = self._read_exploits(exploit.run_id)
                records.append(exploit)
                self._write_exploits(exploit.run_id, records)
        except Exception:
            log.exception("add_exploit failed for run %s", exploit.run_id)

    def update_exploit(self, run_id: str, exploit_id: str, **fields: object) -> None:
        """Update fields on an existing exploit record."""
        try:
            with self._lock:
                records = self._read_exploits(run_id)
                for rec in records:
                    if rec.exploit_id == exploit_id:
                        for k, v in fields.items():
                            setattr(rec, k, v)
                        self._write_exploits(run_id, records)
                        return
                log.warning(
                    "update_exploit: exploit %s not found in run %s",
                    exploit_id,
                    run_id,
                )
        except Exception:
            log.exception(
                "update_exploit failed for %s in run %s",
                exploit_id,
                run_id,
            )

    def find_exploit(
        self,
        run_id: str,
        hypothesis: str,
        file: str,
        function: str,
    ) -> ExploitRecord | None:
        """Look up an exploit by its identifying triple."""
        try:
            with self._lock:
                for rec in self._read_exploits(run_id):
                    if (
                        rec.hypothesis == hypothesis
                        and rec.file == file
                        and rec.function == function
                    ):
                        return rec
                return None
        except Exception:
            log.exception("find_exploit failed for run %s", run_id)
            return None

    def get_exploits(
        self,
        run_id: str,
        status: str | None = None,
    ) -> list[ExploitRecord]:
        """Return exploits for a run, optionally filtered by status."""
        try:
            with self._lock:
                records = self._read_exploits(run_id)
                if status is not None:
                    return [r for r in records if r.status == status]
                return list(records)
        except Exception:
            log.exception("get_exploits failed for %s", run_id)
            return []

    # -- Fixes --

    def add_fix(self, fix: FixRecord) -> None:
        """Persist a new fix record."""
        try:
            with self._lock:
                records = self._read_fixes(fix.run_id)
                records.append(fix)
                self._write_fixes(fix.run_id, records)
        except Exception:
            log.exception("add_fix failed for run %s", fix.run_id)

    def get_fixes(self, run_id: str) -> list[FixRecord]:
        """Return all fixes for a run."""
        try:
            with self._lock:
                return self._read_fixes(run_id)
        except Exception:
            log.exception("get_fixes failed for %s", run_id)
            return []

    # -- Summarization --

    def summarize_progress(self, run_id: str) -> str:
        """Build a progress summary using an LLM.

        Reads status updates and exploit records, formats them into
        a prompt, and calls a lightweight LLM for summarization.
        Falls back to a simple text summary on error.
        """
        updates = self.get_status_updates(run_id)
        exploits = self.get_exploits(run_id)
        fixes = self.get_fixes(run_id)

        if not updates and not exploits:
            return "No progress recorded yet."

        # Build a concise context for the summarizer
        lines: list[str] = []
        lines.append(f"Run {run_id} — latest iteration")
        for u in updates:
            parts = [f"  iter {u.iteration_num}: {u.agent_name}"]
            if u.spawn_agent:
                parts.append(f" [spawned {u.spawn_agent}]")
            elif u.has_spawn_calls:
                parts.append(" [spawned sub-agents]")
            lines.append("".join(parts))

        if exploits:
            by_status: dict[str, int] = {}
            for e in exploits:
                by_status[e.status] = by_status.get(e.status, 0) + 1
            lines.append(f"Exploits: {by_status}")

        if fixes:
            applied = sum(1 for f in fixes if f.applied)
            lines.append(f"Fixes: {len(fixes)} total, {applied} applied")

        context = "\n".join(lines)
        prompt = (
            "Summarize this security audit progress in 2-3 sentences "
            "for a developer. Be concise.\n\n" + context
        )

        try:
            from ra.clients import get_client

            client = get_client(
                self._summary_backend,  # type: ignore[arg-type]
                {"model_name": self._summary_model},
            )
            return client.completion(prompt)
        except Exception:
            log.exception("LLM summary failed, returning raw context")
            return context
