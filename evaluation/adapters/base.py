"""Benchmark adapter contract + lightweight registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from importlib import import_module
from pathlib import Path
from typing import Any, Callable

from evaluation.schemas import PreparedTask, TaskRef, TaskScore

AdapterFactory = Callable[[dict[str, Any]], "BenchAdapter"]


_REGISTRY: dict[str, AdapterFactory] = {}


def register_adapter(name: str) -> Callable[[AdapterFactory], AdapterFactory]:
    """Decorator used by adapters to expose themselves under a stable name."""

    def _wrap(factory: AdapterFactory) -> AdapterFactory:
        if name in _REGISTRY:
            raise ValueError(f"Adapter '{name}' is already registered.")
        _REGISTRY[name] = factory
        return factory

    return _wrap


_BUILTIN_MODULES = {
    "noop": "evaluation.adapters.noop.adapter",
    "cybergym": "evaluation.adapters.cybergym.adapter",
    "bountybench": "evaluation.adapters.bountybench.adapter",
}


def resolve_adapter(name: str, config: dict[str, Any] | None = None) -> "BenchAdapter":
    """Instantiate an adapter by name, loading its module on first use."""

    if name not in _REGISTRY:
        module_path = _BUILTIN_MODULES.get(name)
        if module_path is None:
            raise KeyError(
                f"Unknown adapter '{name}'. Known: "
                f"{sorted(_REGISTRY) + sorted(_BUILTIN_MODULES)}"
            )
        import_module(module_path)
    factory = _REGISTRY[name]
    return factory(config or {})


class BenchAdapter(ABC):
    """Pluggable contract between the harness and any benchmark.

    Implementations own:

    * task enumeration (``list_tasks``),
    * task materialisation on disk (``prepare``),
    * any extra prompt context for the exploit agent (``prompt_extras``),
    * scoring the pipeline result against the benchmark oracle (``score``),
    * cleanup of any external resources (``cleanup``).
    """

    name: str

    @abstractmethod
    def list_tasks(self) -> Iterable[TaskRef]:
        """Yield every task this adapter exposes."""

    @abstractmethod
    def prepare(self, task: TaskRef, workdir: Path) -> PreparedTask:
        """Materialise ``task`` inside ``workdir`` and return its handle."""

    @abstractmethod
    def score(
        self,
        prepared: PreparedTask,
        pipeline_result: dict[str, Any] | None,
        exit_code: int,
    ) -> TaskScore:
        """Score ``pipeline_result`` (the JSON written by ``kai.main``)."""

    def cleanup(self, prepared: PreparedTask) -> None:
        """Release any external resources the adapter held for this task."""

    def filter_tasks(
        self,
        *,
        ids: list[str] | None = None,
        limit: int | None = None,
    ) -> Iterator[TaskRef]:
        """Convenience helper used by the CLI; default impl iterates ``list_tasks``."""

        count = 0
        wanted: set[str] | None = set(ids) if ids else None
        for task in self.list_tasks():
            if wanted is not None and task.task_id not in wanted:
                continue
            yield task
            count += 1
            if limit is not None and count >= limit:
                break
