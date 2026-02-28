"""Structured JSON printer for CloudWatch-compatible logging.

Drop-in replacement for VerbosePrinter that emits one JSON line per
event.  No rich dependency — output is plain text suitable for log
aggregation services.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

from ra.core.types import CodeBlock, RLMIteration, RLMMetadata

_DEFAULT_PREVIEW = 500


def _preview_limit() -> int:
    """Read preview character limit from env, default 500."""
    raw = os.environ.get("KAI_LOG_PREVIEW_CHARS", "")
    try:
        return int(raw)
    except (ValueError, TypeError):
        return _DEFAULT_PREVIEW


def _oneline(text: str, limit: int | None = None) -> str:
    """Collapse multi-line text to a single line, truncated."""
    if limit is None:
        limit = _preview_limit()
    flat = " ".join(text.split())
    if len(flat) > limit:
        return flat[:limit] + "..."
    return flat


class StructuredPrinter:
    """Emit one JSON line per RLM event.

    Same public interface as ``VerbosePrinter`` so the two can be
    swapped via ``create_printer()``.
    """

    def __init__(
        self,
        enabled: bool = True,
        name: str = "",
        depth: int = 0,
        log_file: str = "",
    ) -> None:
        self.enabled = enabled
        self.name = name
        self.depth = depth
        self._log_fh = None
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            self._log_fh = open(log_file, "a")  # noqa: SIM115
        self._iteration_count = 0

    def _label(self) -> str:
        if not self.name:
            return "RLM"
        return self.name

    def _emit(self, event: str, **data: Any) -> None:
        """Write a single JSON line to stdout and optional log file."""
        if not self.enabled:
            return
        record = {"event": event, "agent": self._label(), "depth": self.depth}
        record.update(data)
        line = json.dumps(record, default=str)
        print(line, file=sys.__stdout__, flush=True)
        if self._log_fh is not None:
            print(line, file=self._log_fh, flush=True)

    # -- public interface (mirrors VerbosePrinter) --

    def print_header(
        self,
        backend: str,
        model: str,
        environment: str,
        max_iterations: int,
        max_depth: int,
        other_backends: list[str] | None = None,
    ) -> None:
        if not self.enabled:
            return
        self._emit(
            "header",
            backend=backend,
            model=model,
            environment=environment,
            max_iterations=max_iterations,
            max_depth=max_depth,
            other_backends=other_backends,
        )

    def print_metadata(self, metadata: RLMMetadata) -> None:
        if not self.enabled:
            return
        model = metadata.backend_kwargs.get("model_name", "unknown")
        other = list(metadata.other_backends) if metadata.other_backends else None
        self.print_header(
            backend=metadata.backend,
            model=model,
            environment=metadata.environment_type,
            max_iterations=metadata.max_iterations,
            max_depth=metadata.max_depth,
            other_backends=other,
        )

    def print_iteration_start(self, iteration: int) -> None:
        if not self.enabled:
            return
        self._iteration_count = iteration
        self._emit("iteration_start", iteration=iteration)

    def print_waiting(self, iteration: int) -> None:
        if not self.enabled:
            return
        self._emit("waiting", iteration=iteration)

    def print_completion(
        self, response: Any, iteration_time: float | None = None
    ) -> None:
        if not self.enabled:
            return
        text = str(response) if not isinstance(response, str) else response
        self._emit(
            "completion",
            iteration=self._iteration_count,
            response_length=len(text),
            response_preview=_oneline(text),
            iteration_time=iteration_time,
        )

    def print_pre_execution(self, code: str) -> None:
        if not self.enabled:
            return
        self._emit(
            "pre_execution",
            iteration=self._iteration_count,
            code_length=len(code),
        )

    def print_code_execution(self, code_block: CodeBlock) -> None:
        if not self.enabled:
            return
        result = code_block.result
        stdout = str(result.stdout) if result.stdout else ""
        stderr = str(result.stderr) if result.stderr else ""
        self._emit(
            "code_execution",
            iteration=self._iteration_count,
            code_length=len(code_block.code),
            has_stdout=bool(stdout.strip()),
            has_stderr=bool(stderr.strip()),
            execution_time=result.execution_time,
            subcalls=len(result.rlm_calls),
        )

    def print_subcall(
        self,
        model: str,
        prompt_preview: str,
        response_preview: str,
        execution_time: float | None = None,
    ) -> None:
        if not self.enabled:
            return
        self._emit(
            "subcall",
            model=model,
            prompt_preview=_oneline(prompt_preview),
            response_preview=_oneline(response_preview),
            execution_time=execution_time,
        )

    def print_iteration(self, iteration: RLMIteration, iteration_num: int) -> None:
        if not self.enabled:
            return
        self.print_iteration_start(iteration_num)
        self.print_completion(iteration.response, iteration.iteration_time)
        for code_block in iteration.code_blocks:
            self.print_code_execution(code_block)
            for call in code_block.result.rlm_calls:
                self.print_subcall(
                    model=call.root_model,
                    prompt_preview=str(call.prompt) if call.prompt else "",
                    response_preview=(str(call.response) if call.response else ""),
                    execution_time=call.execution_time,
                )

    def print_extend(
        self,
        old_max: int,
        new_max: int,
        granted: int,
        cap: int,
    ) -> None:
        """Emit an iteration-extension event."""
        if not self.enabled:
            return
        self._emit(
            "extend_iterations",
            old_max=old_max,
            new_max=new_max,
            granted=granted,
            cap=cap,
        )

    def print_final_answer(self, answer: Any) -> None:
        if not self.enabled:
            return
        text = str(answer) if not isinstance(answer, str) else answer
        self._emit(
            "final_answer",
            answer_length=len(text),
            answer_preview=_oneline(text),
        )

    def print_summary(
        self,
        total_iterations: int,
        total_time: float,
        usage_summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return
        data: dict[str, Any] = {
            "total_iterations": total_iterations,
            "total_time": round(total_time, 2),
        }
        if usage_summary:
            total_input = sum(
                m.get("total_input_tokens", 0)
                for m in usage_summary.get("model_usage_summaries", {}).values()
            )
            total_output = sum(
                m.get("total_output_tokens", 0)
                for m in usage_summary.get("model_usage_summaries", {}).values()
            )
            if total_input or total_output:
                data["input_tokens"] = total_input
                data["output_tokens"] = total_output
        self._emit("summary", **data)
