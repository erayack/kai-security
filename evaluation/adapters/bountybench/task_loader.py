"""BountyBench on-disk task layout helpers.

The upstream BountyBench layout (see
https://github.com/bountybench/bountybench) is:

```
bountytasks/
└── <system>/
    ├── metadata.json              # target_host, invariant_thresholds, info
    ├── codebase/                  # source tree (git submodule upstream)
    └── bounties/
        └── bounty_<N>/
            ├── bounty_metadata.json   # CWE, CVE, severity, exploit_prompt
            ├── setup_files/            # docker-compose, env files, …
            ├── verify_files/           # verify.sh
            ├── exploit_files/          # working dir for produced PoCs
            ├── patch_files/            # patch -> codebase path mappings
            └── writeup/                # human-written disclosure (HTML/MD)
```

The DETECT-mode v1 adapter only needs the bounty's CWE list, the system's
codebase directory and a short human-readable description, so this module
intentionally surfaces just enough of the layout to support that path. The
richer fields (docker-compose, verify.sh, patch mappings) are exposed via
``BountyTask.raw_metadata`` so EXPLOIT/PATCH follow-ups can grow without
having to rewrite this loader.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOG = logging.getLogger("evaluation.adapters.bountybench.task_loader")

CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


@dataclass
class BountyTask:
    """Materialised handle for a single ``<system>/bounty_<N>`` task.

    Attributes:
        system: The owning project directory under ``bountytasks/``.
        bounty: The bounty subdir name (e.g. ``bounty_0``).
        task_dir: Absolute path to the ``<system>/`` directory.
        bounty_dir: Absolute path to ``<system>/bounties/<bounty>/``.
        codebase_dir: Absolute path to the codebase to be shipped to the
            agent. Defaults to ``<system>/codebase`` and falls back to
            ``<system>/`` itself if the submodule has not been
            initialised.
        cwes: CWE identifiers parsed out of ``bounty_metadata.json``
            (uppercased, e.g. ``["CWE-639"]``). A single CWE is the norm
            but upstream sometimes records multiple in one string.
        severity: Free-form severity string ("7.5", "high", …) verbatim
            from the metadata.
        cve: CVE identifier or empty string.
        exploit_prompt: Optional human-written hint from upstream.
        task_info: ``metadata.json['info']`` field (credentials, setup
            tips) at the system level.
        target_host: ``metadata.json['target_host']`` value, useful for
            EXPLOIT mode (unused in DETECT v1).
        writeup_text: Best-effort plaintext disclosure writeup, or empty
            string when no writeup file exists.
        raw_bounty_metadata: Untouched ``bounty_metadata.json`` content.
        raw_task_metadata: Untouched ``metadata.json`` content.
    """

    system: str
    bounty: str
    task_dir: Path
    bounty_dir: Path
    codebase_dir: Path
    cwes: list[str] = field(default_factory=list)
    severity: str = ""
    cve: str = ""
    exploit_prompt: str = ""
    task_info: str = ""
    target_host: str = ""
    writeup_text: str = ""
    raw_bounty_metadata: dict[str, Any] = field(default_factory=dict)
    raw_task_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def task_id(self) -> str:
        """Canonical ``<system>/<bounty>`` identifier."""

        return f"{self.system}/{self.bounty}"


def _read_json(path: Path) -> dict[str, Any]:
    """Read ``path`` as JSON; return ``{}`` if missing or unparseable."""

    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        LOG.warning("bountybench: %s is not valid JSON", path)
        return {}


def _extract_cwes(metadata: dict[str, Any]) -> list[str]:
    """Pull CWE identifiers out of a bounty's metadata blob.

    Upstream typically stores a *descriptive* CWE string of the form
    ``"CWE-639: Authorization Bypass Through User-Controlled Key"`` under
    the ``CWE`` key. A small number of bounties (e.g. composio) embed
    several CWEs in one string. We accept either ``CWE`` or ``cwe`` keys
    and return the identifiers uppercased and de-duplicated while
    preserving order.
    """

    raw = metadata.get("CWE") or metadata.get("cwe") or ""
    if isinstance(raw, list):
        candidates = " ".join(str(item) for item in raw)
    else:
        candidates = str(raw)
    seen: set[str] = set()
    ordered: list[str] = []
    for match in CWE_RE.finditer(candidates):
        cwe = match.group(0).upper()
        if cwe not in seen:
            seen.add(cwe)
            ordered.append(cwe)
    return ordered


def _load_writeup(bounty_dir: Path) -> str:
    """Best-effort plaintext extraction of the bounty's writeup.

    HTML tags are stripped with a regex (we only need it as agent
    context; correctness of parsing is not load-bearing) and the file is
    read with ``errors='replace'`` so a malformed writeup never crashes
    enumeration.
    """

    writeup_dir = bounty_dir / "writeup"
    if not writeup_dir.is_dir():
        return ""
    for name in ("writeup.md", "writeup.txt", "writeup.html"):
        path = writeup_dir / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            LOG.warning("bountybench: failed to read writeup at %s", path)
            return ""
        if name.endswith(".html"):
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
        return text
    return ""


def _resolve_codebase(task_dir: Path) -> Path:
    """Return the ``codebase/`` submodule path the agent should inspect.

    Always ``task_dir/codebase`` — even when it is empty/uninitialised. We must
    NOT fall back to ``task_dir`` itself: it contains ``bounties/``
    (``bounty_metadata.json`` plus the reference exploit/patch), so
    materialising it as the agent's repo would hand the agent the ground-truth
    oracle. The caller detects an empty codebase and either initialises the
    submodule or fails the task as an infra error.
    """

    return task_dir / "codebase"


def load_bounty_task(task_dir: Path, bounty_dir: Path) -> BountyTask:
    """Hydrate a :class:`BountyTask` from on-disk metadata.

    Args:
        task_dir: Absolute path to ``<bountybench_root>/<system>``.
        bounty_dir: Absolute path to ``<task_dir>/bounties/<bounty>``.

    Returns:
        A fully populated :class:`BountyTask`. Missing files are
        tolerated (they just produce empty string fields) so the loader
        never raises for a partially-formed task on disk.
    """

    task_metadata = _read_json(task_dir / "metadata.json")
    bounty_metadata = _read_json(bounty_dir / "bounty_metadata.json")

    severity = bounty_metadata.get("severity", "")
    if not isinstance(severity, str):
        severity = str(severity)

    return BountyTask(
        system=task_dir.name,
        bounty=bounty_dir.name,
        task_dir=task_dir,
        bounty_dir=bounty_dir,
        codebase_dir=_resolve_codebase(task_dir),
        cwes=_extract_cwes(bounty_metadata),
        severity=severity,
        cve=str(bounty_metadata.get("CVE") or bounty_metadata.get("cve") or ""),
        exploit_prompt=str(bounty_metadata.get("exploit_prompt") or ""),
        task_info=str(task_metadata.get("info") or ""),
        target_host=str(task_metadata.get("target_host") or ""),
        writeup_text=_load_writeup(bounty_dir),
        raw_bounty_metadata=bounty_metadata,
        raw_task_metadata=task_metadata,
    )


def iter_bounty_tasks(root: Path) -> Iterator[BountyTask]:
    """Yield every ``<system>/<bounty>`` task under ``root``.

    ``root`` must point at the ``bountytasks/`` directory (the one that
    contains per-system folders, *not* the outer ``bountybench`` repo
    checkout). Tasks are emitted in deterministic order — system name,
    then numeric bounty index — so smoke runs are reproducible.

    Args:
        root: ``bountytasks/`` directory.

    Yields:
        :class:`BountyTask` instances. Systems with no ``bounties/``
        subdirectory are skipped silently; bounty directories that fail
        to parse are skipped with a warning.
    """

    if not root.is_dir():
        raise FileNotFoundError(f"bountybench_root does not exist: {root}")

    for system_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        bounties_dir = system_dir / "bounties"
        if not bounties_dir.is_dir():
            continue
        bounty_dirs = sorted(
            (p for p in bounties_dir.iterdir() if p.is_dir() and _is_bounty(p)),
            key=_bounty_sort_key,
        )
        for bounty_dir in bounty_dirs:
            try:
                yield load_bounty_task(system_dir, bounty_dir)
            except OSError as exc:
                LOG.warning(
                    "bountybench: skipping %s/%s: %s",
                    system_dir.name,
                    bounty_dir.name,
                    exc,
                )


def _is_bounty(path: Path) -> bool:
    return path.name.startswith("bounty_")


def _bounty_sort_key(path: Path) -> tuple[int, str]:
    """Sort ``bounty_<N>`` directories numerically when possible."""

    suffix = path.name.split("_", 1)[-1]
    try:
        return (int(suffix), path.name)
    except ValueError:
        return (10_000, path.name)
