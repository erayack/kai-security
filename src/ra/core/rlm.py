import logging
import os
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable

from ra.clients import BaseLM, get_client
from ra.core.lm_handler import LMHandler
from ra.core.types import (
    ClientBackend,
    CodeBlock,
    EnvironmentType,
    REPLResult,
    RLMChatCompletion,
    RLMIteration,
    RLMMetadata,
    UsageSummary,
)
from ra.environments import BaseEnv, SupportsPersistence, get_environment
from ra.exceptions import LMError, RecursiveAgentError, SetupRLMError
from ra.logger import RecursiveAgentLogger, create_printer
from ra.utils.parsing import (
    find_code_blocks,
    find_final_answer,
    format_iteration,
)
from ra.utils.prompts import (
    RLM_SYSTEM_PROMPT,
    QueryMetadata,
    build_rlm_system_prompt,
    build_user_prompt,
)
from ra.utils.rlm_utils import filter_sensitive_keys

_DEFAULT_ITER_WALL_CAP_S = 600.0
_DEFAULT_MAX_BLOCKS_PER_ITER = 6


def _read_iter_wall_cap() -> float:
    """Read ``KAI_ITER_WALL_CAP`` (seconds) from env; 0 disables the cap."""
    raw = os.environ.get("KAI_ITER_WALL_CAP")
    if raw is None or raw == "":
        return _DEFAULT_ITER_WALL_CAP_S
    try:
        value = float(raw)
    except ValueError:
        return _DEFAULT_ITER_WALL_CAP_S
    return max(0.0, value)


def _read_max_blocks_per_iter() -> int:
    """Read ``KAI_MAX_BLOCKS_PER_ITER`` from env; 0 disables the cap."""
    raw = os.environ.get("KAI_MAX_BLOCKS_PER_ITER")
    if raw is None or raw == "":
        return _DEFAULT_MAX_BLOCKS_PER_ITER
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_BLOCKS_PER_ITER
    return max(0, value)


def _resolve_final_answer(
    *,
    iteration: RLMIteration,
    environment: BaseEnv,
) -> str | None:
    """Resolve a final answer for ``iteration``.

    When the harness truncated the iteration (per-iter wall-clock or
    block-count cap fired), suppress final-answer detection: the
    model's FINAL_VAR / FINAL marker almost always sits at the end of
    its response, and the code blocks that BUILD the referenced
    variable were dropped. Honouring the marker exits the loop with an
    empty / partial result. Returning ``None`` here lets the loop
    advance to iter N+1, where the model sees the truncation notice
    and re-emits the final answer after retrying the truncated work.
    """
    if iteration.truncation_notice:
        return None
    return find_final_answer(iteration.response, environment=environment)


def _format_truncation_notice(
    *,
    iteration_num: int,
    iteration_time: float,
    wall_cap: float,
    max_blocks: int,
    total_emitted: int,
    executed: int,
    wall_capped_at: int | None,
    block_capped_at: int | None,
) -> str | None:
    """Return a harness notice when a per-iter cap dropped any code blocks.

    The notice is appended to the next iteration's user-role prompt by
    :func:`ra.utils.parsing.format_iteration` so the model knows
    exactly what was capped and how to adapt.
    """
    dropped = total_emitted - executed
    if dropped <= 0 and wall_capped_at is None and block_capped_at is None:
        return None
    parts = [
        f"[harness notice] Iteration {iteration_num} executed "
        f"{executed} of the {total_emitted} code blocks you emitted; "
        f"the remaining {dropped} were dropped before execution."
    ]
    if block_capped_at is not None:
        parts.append(
            f"Reason: per-iteration block cap (KAI_MAX_BLOCKS_PER_ITER={max_blocks})."
        )
    if wall_capped_at is not None:
        parts.append(
            f"Reason: wall-clock cap of {wall_cap:.0f}s reached "
            f"after {iteration_time:.0f}s "
            f"(KAI_ITER_WALL_CAP={wall_cap:.0f})."
        )
    parts.append(
        "Emit a SHORTER response next iteration. Pick ONE concrete "
        "action: read a file, spawn ONE sub-agent, run ONE focused "
        "llm_query, or write the PoC. Do not chain multiple sub-agent "
        "spawns in a single iteration. After you see the result, "
        "decide the next single action."
    )
    return "\n".join(parts)


class RLM:
    """
    Recursive Language Model class that the user instantiates and runs on their tasks.

    Each completion() call spawns its own environment and LM handler, which are
    cleaned up when the call completes.
    """

    def __init__(
        self,
        backend: ClientBackend = "openai",
        backend_kwargs: dict[str, Any] | None = None,
        environment: EnvironmentType = "local",
        environment_kwargs: dict[str, Any] | None = None,
        depth: int = 0,
        max_depth: int = 1,
        max_iterations: int = 30,
        custom_system_prompt: str | None = None,
        other_backends: list[ClientBackend] | None = None,
        other_backend_kwargs: list[dict[str, Any]] | None = None,
        query_model: str | None = None,
        logger: RecursiveAgentLogger | None = None,
        verbose: bool = False,
        log_file: str = "",
        log_structured: bool = False,
        persistent: bool = False,
        name: str = "",
        on_iteration: Any | None = None,
        on_extend: Callable[[int], int | None] | None = None,
        max_iterations_limit: int | None = None,
        on_early_stop: Callable[[int], str | None] | None = None,
    ):
        """
        Args:
            backend: The backend to use for the RLM.
            backend_kwargs: The kwargs to pass to the backend.
            environment: The environment to use for the RLM.
            environment_kwargs: The kwargs to pass to the environment.
            depth: The current depth of the RLM (0-indexed).
            max_depth: The maximum depth of the RLM. Currently, only depth 1 is supported.
            max_iterations: The maximum number of iterations of the RLM.
            custom_system_prompt: The custom system prompt to use for the RLM.
            other_backends: A list of other client backends that the environments can use to make sub-calls.
            other_backend_kwargs: The kwargs to pass to the other client backends (ordered to match other_backends).
            logger: The logger to use for the RLM.
            verbose: Whether to print verbose output in rich to console.
            persistent: If True, reuse the environment across completion() calls for multi-turn conversations.
            on_extend: Callback invoked when iterations reach the current limit.
                Receives the current iteration count and returns the number of
                extra iterations to grant (or ``None``/0 to stop).
            max_iterations_limit: Hard ceiling on total iterations including
                extensions.  Defaults to ``max_iterations`` (no extension).
            on_early_stop: Callback invoked when a final answer is detected.
                Receives the current iteration count and returns a nudge
                prompt string to inject (suppressing the final answer) or
                ``None`` to accept the answer normally.
        """
        # Store config for spawning per-completion
        self.backend = backend
        self.backend_kwargs = backend_kwargs
        self.environment_type = environment
        self.environment_kwargs = (
            environment_kwargs.copy() if environment_kwargs is not None else {}
        )
        # Validate other_backends: currently only support one additional backend
        if other_backends is not None:
            if len(other_backends) != 1:
                raise ValueError(
                    "We currently only support one additional backend for the recursive sub-calls! "
                    "This model will be the model used for recursive sub-calls, but this will change in the future"
                )

        self.other_backends = other_backends
        self.other_backend_kwargs = other_backend_kwargs
        self.query_model = query_model

        self.depth = depth
        self.max_depth = max_depth
        self.max_iterations = max_iterations
        self.system_prompt = (
            custom_system_prompt if custom_system_prompt else RLM_SYSTEM_PROMPT
        )
        self.name = name
        self.logger = logger
        self.verbose = create_printer(
            enabled=verbose,
            name=name,
            depth=depth,
            log_file=log_file,
            structured=log_structured,
        )

        # Persistence support
        self.persistent = persistent
        self._persistent_env: SupportsPersistence | None = None

        self.on_iteration = on_iteration
        self.on_extend = on_extend
        self.on_early_stop = on_early_stop
        self.max_iterations_limit = (
            max_iterations_limit if max_iterations_limit is not None else max_iterations
        )

        # Cooperative cancellation: parent can signal this RLM to stop
        self._cancel_event: threading.Event | None = self.environment_kwargs.pop(
            "cancel_event", None
        )

        # Validate persistence support at initialization
        if self.persistent:
            self._validate_persistent_environment_support()

        # Log metadata if logger is provided
        if self.logger or verbose:
            metadata = RLMMetadata(
                root_model=backend_kwargs.get("model_name", "unknown")
                if backend_kwargs
                else "unknown",
                max_depth=max_depth,
                max_iterations=max_iterations,
                backend=backend,
                backend_kwargs=filter_sensitive_keys(backend_kwargs)
                if backend_kwargs
                else {},
                environment_type=environment,
                environment_kwargs=filter_sensitive_keys(environment_kwargs)
                if environment_kwargs
                else {},
                other_backends=list(other_backends) if other_backends else None,
                name=name,
                depth=depth,
            )
            if self.logger:
                self.logger.log_metadata(metadata)
            self.verbose.print_metadata(metadata)

    @contextmanager
    def _spawn_completion_context(self, prompt: str | dict[str, Any]):
        """
        Spawn an LM handler and environment for a single completion call.

        When persistent=True, the environment is reused across calls.
        When persistent=False (default), creates fresh environment each call.
        """
        # Create client and wrap in handler
        client: BaseLM = get_client(self.backend, self.backend_kwargs or {})

        # Create other_backend_client if provided (for depth=1 routing)
        other_backend_client: BaseLM | None = None
        if self.other_backends and self.other_backend_kwargs:
            other_backend_client = get_client(
                self.other_backends[0], self.other_backend_kwargs[0]
            )

        lm_handler = LMHandler(client, other_backend_client=other_backend_client)

        # Register other clients to be available as sub-call options (by model name)
        if self.other_backends and self.other_backend_kwargs:
            for backend, kwargs in zip(
                self.other_backends, self.other_backend_kwargs, strict=True
            ):
                other_client: BaseLM = get_client(backend, kwargs)
                if other_client.model_name is None:
                    raise LMError(
                        f"Backend {backend!r} returned a client without model_name"
                    )
                lm_handler.register_client(other_client.model_name, other_client)

        # Register a dedicated client for llm_query if query_model set
        if self.query_model:
            query_kwargs = dict(self.backend_kwargs or {})
            query_kwargs["model_name"] = self.query_model
            query_client: BaseLM = get_client(self.backend, query_kwargs)
            lm_handler.register_client(self.query_model, query_client)

        lm_handler.start()

        # Environment: reuse if persistent, otherwise create fresh
        if self.persistent and self._persistent_env is not None:
            environment = self._persistent_env
            # Defensive check: ensure environment supports persistence methods
            if not self._env_supports_persistence(environment):
                raise RuntimeError(
                    f"Persistent environment of type '{type(environment).__name__}' does not "
                    f"implement required methods (update_handler_address, add_context, get_context_count). "
                    f"This should have been caught at initialization."
                )
            environment.update_handler_address((lm_handler.host, lm_handler.port))
            environment.add_context(prompt)
        else:
            env_kwargs = self.environment_kwargs.copy()
            env_kwargs["lm_handler_address"] = (lm_handler.host, lm_handler.port)
            env_kwargs["context_payload"] = prompt
            env_kwargs["depth"] = self.depth + 1  # Environment depth is RLM depth + 1
            if self.query_model:
                env_kwargs["query_model"] = self.query_model
            environment: BaseEnv = get_environment(self.environment_type, env_kwargs)

            if self.persistent:
                self._persistent_env = environment  # type: ignore[assignment]

        try:
            yield lm_handler, environment
        finally:
            lm_handler.stop()
            if not self.persistent:
                cleanup = getattr(environment, "cleanup", None)
                if cleanup is None or not callable(cleanup):
                    raise SetupRLMError(
                        f"Environment {type(environment).__name__}"
                        " missing callable cleanup()"
                    )
                cleanup()

    def _setup_prompt(self, prompt: str | dict[str, Any]) -> list[dict[str, Any]]:
        """
        Setup the system prompt for the RLM. Also include metadata about the prompt and build
        up the initial message history.
        """
        metadata = QueryMetadata(prompt)
        message_history = build_rlm_system_prompt(
            system_prompt=self.system_prompt, query_metadata=metadata
        )

        return message_history

    def completion(
        self, prompt: str | dict[str, Any], root_prompt: str | None = None
    ) -> RLMChatCompletion:
        """
        Recursive Language Model completion call. This is the main entry point for querying an RLM, and
        can replace a regular LM completion call.

        Spawns its own environment and LM handler for the duration of this call.

        Args:
            prompt: A single string or dictionary of messages to pass as context to the model.
            root_prompt: We allow the RLM's root LM to see a (small) prompt that the user specifies. A common example of this
            is if the user is asking the RLM to answer a question, we can pass the question as the root prompt.
        Returns:
            A final answer as a string.
        """
        time_start = time.perf_counter()

        # If we're at max depth, the RLM is an LM, so we fallback to the regular LM.
        if self.depth >= self.max_depth:
            t0 = time.perf_counter()
            response, usage, model_name = self._fallback_answer(prompt)
            return RLMChatCompletion(
                root_model=model_name,
                prompt=prompt,
                response=response,
                usage_summary=usage,
                execution_time=time.perf_counter() - t0,
            )

        with self._spawn_completion_context(prompt) as (lm_handler, environment):
            message_history = self._setup_prompt(prompt)
            child_usage = UsageSummary(model_usage_summaries={})
            emitted_iterations = 0

            effective_max = self.max_iterations
            i = 0
            while i < effective_max:
                # Cooperative cancellation: parent timed out
                if self._cancel_event is not None and self._cancel_event.is_set():
                    break

                # Current prompt = message history + additional prompt suffix
                context_count = (
                    environment.get_context_count()
                    if isinstance(environment, SupportsPersistence)
                    else 1
                )
                history_count = (
                    environment.get_history_count()
                    if isinstance(environment, SupportsPersistence)
                    else 0
                )
                current_prompt = message_history + [
                    build_user_prompt(root_prompt, i, context_count, history_count)
                ]

                self.verbose.print_waiting(i + 1)

                try:
                    iteration: RLMIteration = self._completion_turn(
                        prompt=current_prompt,
                        lm_handler=lm_handler,
                        environment=environment,
                        iteration_num=i + 1,
                    )
                except Exception as exc:
                    if isinstance(exc, RecursiveAgentError):
                        exc.enrich(
                            agent_name=self.name,
                            depth=self.depth,
                            iteration_num=i + 1,
                            model=(
                                self.backend_kwargs.get("model_name")
                                if self.backend_kwargs
                                else None
                            ),
                        )
                    logging.getLogger(__name__).error(
                        "LLM call failed on iteration %d: %s — "
                        "falling through to default answer",
                        i + 1,
                        exc,
                    )
                    break

                # Collect child usage from spawn calls.
                # Snapshot each rlm_calls list to avoid racing with
                # orphaned daemon threads from timed-out code blocks.
                for cb in iteration.code_blocks:
                    for call in list(cb.result.rlm_calls):
                        child_usage = child_usage.merge(call.usage_summary)

                # Check if RLM is done and has a final answer.
                final_answer = _resolve_final_answer(
                    iteration=iteration, environment=environment
                )
                iteration.final_answer = final_answer

                # Suppress early termination when hook says to continue
                nudge: str | None = None
                if final_answer is not None and self.on_early_stop:
                    nudge = self.on_early_stop(i + 1)
                    if nudge is not None:
                        final_answer = None
                        iteration.final_answer = None
                        self.verbose.print_nudge(i + 1)

                # Fire on_iteration BEFORE any downstream processing
                # so rollout / status hooks are guaranteed to run even
                # if later code (logger, formatting) raises.
                if self.on_iteration:
                    self.on_iteration(iteration, i + 1)
                    emitted_iterations += 1

                # If logger is used, log the iteration.
                if self.logger:
                    self.logger.log(iteration)

                if final_answer is not None:
                    time_end = time.perf_counter()
                    usage = lm_handler.get_usage_summary().merge(child_usage)
                    self.verbose.print_final_answer(final_answer)
                    self.verbose.print_summary(
                        i + 1, time_end - time_start, usage.to_dict()
                    )

                    # Store message history in persistent environment
                    if self.persistent and isinstance(environment, SupportsPersistence):
                        environment.add_history(message_history)

                    return RLMChatCompletion(
                        root_model=self.backend_kwargs.get("model_name", "unknown")
                        if self.backend_kwargs
                        else "unknown",
                        prompt=prompt,
                        response=final_answer,
                        usage_summary=usage,
                        execution_time=time_end - time_start,
                    )

                # Format the iteration for the next prompt.
                new_messages = format_iteration(iteration)

                # Update message history with the new messages.
                message_history.extend(new_messages)

                # Inject nudge if early stop was suppressed
                if nudge is not None:
                    message_history.append({"role": "user", "content": nudge})

                i += 1

                # At the boundary, ask if we should extend
                if i == effective_max and self.on_extend:
                    extra = self.on_extend(i)
                    if extra and extra > 0:
                        old_max = effective_max
                        effective_max = min(
                            effective_max + extra,
                            self.max_iterations_limit,
                        )
                        granted = effective_max - old_max
                        self.verbose.print_extend(
                            old_max,
                            effective_max,
                            granted,
                            self.max_iterations_limit,
                        )

            # Default behavior: we run out of iterations, provide one final answer
            time_end = time.perf_counter()
            final_answer = self._default_answer(
                message_history, lm_handler, environment=environment
            )
            usage = lm_handler.get_usage_summary().merge(child_usage)
            if self.on_iteration and emitted_iterations == 0:
                # If the first model turn fails before any real iteration is
                # emitted, persist a synthetic terminal iteration so rollout
                # hooks still create the per-agent JSONL file.
                self.on_iteration(
                    RLMIteration(
                        prompt=prompt,
                        response=final_answer,
                        code_blocks=[],
                        final_answer=final_answer,
                    ),
                    1,
                )
            self.verbose.print_final_answer(final_answer)
            self.verbose.print_summary(
                effective_max, time_end - time_start, usage.to_dict()
            )

            # Store message history in persistent environment
            if self.persistent and isinstance(environment, SupportsPersistence):
                environment.add_history(message_history)

            return RLMChatCompletion(
                root_model=self.backend_kwargs.get("model_name", "unknown")
                if self.backend_kwargs
                else "unknown",
                prompt=prompt,
                response=final_answer,
                usage_summary=usage,
                execution_time=time_end - time_start,
            )

    def _completion_turn(
        self,
        prompt: str | dict[str, Any] | list[dict[str, Any]],
        lm_handler: LMHandler,
        environment: BaseEnv,
        iteration_num: int = 0,
    ) -> RLMIteration:
        """
        Perform a single iteration of the RLM, including prompting the model
        and code execution + tool execution.

        Per-iteration caps (both default-on, both env-overridable):
        * ``KAI_ITER_WALL_CAP`` (default 600s): wall-clock budget for the
          for-loop over code blocks. When tripped, the remaining blocks
          are dropped and surfaced to the model in iteration N+1's
          prompt.
        * ``KAI_MAX_BLOCKS_PER_ITER`` (default 6): hard cap on how many
          of the model's emitted code blocks the harness will execute
          in a single iteration. Dropped blocks are surfaced the same way.

        Both caps were introduced after R5–R16 showed the model
        collapsing the whole pipeline into a single 30+ code-block
        iteration that consumed the entire wall-clock budget.
        """
        iter_start = time.perf_counter()
        response = lm_handler.completion(prompt)  # type: ignore[arg-type]
        llm_time = time.perf_counter() - iter_start

        # Print LLM response immediately
        self.verbose.print_iteration_start(iteration_num)
        self.verbose.print_completion(response, llm_time)

        code_block_strs = find_code_blocks(response)
        wall_cap = _read_iter_wall_cap()
        max_blocks = _read_max_blocks_per_iter()

        total_emitted = len(code_block_strs)
        if max_blocks > 0 and total_emitted > max_blocks:
            block_capped_at = max_blocks
            executable = code_block_strs[:max_blocks]
        else:
            block_capped_at = None
            executable = code_block_strs

        code_blocks: list[CodeBlock] = []
        wall_capped_at: int | None = None
        for idx, code_block_str in enumerate(executable):
            elapsed = time.perf_counter() - iter_start
            if wall_cap > 0 and elapsed >= wall_cap:
                wall_capped_at = idx
                break
            self.verbose.print_pre_execution(code_block_str)
            # Clamp this block's exec timeout to the remaining wall budget
            # so a single long-running block can't blow past the cap.
            block_max_time: float | None = None
            if wall_cap > 0:
                block_max_time = max(1.0, wall_cap - elapsed)
            code_result: REPLResult = environment.execute_code(
                code_block_str, max_time=block_max_time
            )
            cb = CodeBlock(code=code_block_str, result=code_result)
            code_blocks.append(cb)
            self.verbose.print_code_execution(cb)
            for call in cb.result.rlm_calls:
                self.verbose.print_subcall(
                    model=call.root_model,
                    prompt_preview=str(call.prompt) if call.prompt else "",
                    response_preview=str(call.response) if call.response else "",
                    execution_time=call.execution_time,
                )

        iteration_time = time.perf_counter() - iter_start
        executed = len(code_blocks)
        dropped = total_emitted - executed
        truncation_notice = _format_truncation_notice(
            iteration_num=iteration_num,
            iteration_time=iteration_time,
            wall_cap=wall_cap,
            max_blocks=max_blocks,
            total_emitted=total_emitted,
            executed=executed,
            wall_capped_at=wall_capped_at,
            block_capped_at=block_capped_at,
        )

        return RLMIteration(
            prompt=prompt,
            response=response,
            code_blocks=code_blocks,
            iteration_time=iteration_time,
            dropped_blocks=dropped,
            truncation_notice=truncation_notice,
        )

    def _default_answer(
        self,
        message_history: list[dict[str, Any]],
        lm_handler: LMHandler,
        environment: BaseEnv | None = None,
    ) -> str:
        """
        Default behavior if the RLM runs out of iterations and does not find a final answer.
        It will take the message history, and try to generate a final answer from it.

        If an environment is provided, FINAL_VAR references in the
        response are resolved against the REPL namespace.
        """
        current_prompt = message_history + [
            {
                "role": "user",
                "content": (
                    "You have run out of iterations. Provide ONLY "
                    "your final result — no conversation log, no "
                    "intermediate steps, no explanation of your "
                    "process. If you computed a result in your REPL, "
                    "output just the result data via FINAL_VAR. "
                    "If you have partial findings, summarize them "
                    "concisely."
                ),
            }
        ]
        try:
            response = lm_handler.completion(current_prompt)
        except Exception as exc:
            # LLM call failed (e.g. context window exceeded).
            # Try to recover final_result from the environment.
            fallback = None
            if environment is not None:
                try:
                    fallback = find_final_answer(
                        "FINAL_VAR(final_result)",
                        environment=environment,
                    )
                except Exception:
                    pass
            response = fallback or f"Error: _default_answer failed: {exc}"

        # Execute any REPL code blocks so variables are set before
        # resolving FINAL_VAR references.
        if environment is not None:
            for code_block in find_code_blocks(response):
                try:
                    environment.execute_code(code_block)
                except Exception:
                    pass

        # Resolve FINAL_VAR against the environment if available.
        resolved = find_final_answer(response, environment=environment)
        if resolved is not None:
            response = resolved

        if self.logger:
            self.logger.log(
                RLMIteration(
                    prompt=current_prompt,
                    response=response,
                    final_answer=response,
                    code_blocks=[],
                )
            )

        return response

    def _fallback_answer(
        self, message: str | dict[str, Any]
    ) -> tuple[str, UsageSummary, str]:
        """Fallback when at max depth — plain LM call.

        Returns:
            (response, usage_summary, model_name)
        """
        client: BaseLM = get_client(self.backend, self.backend_kwargs or {})
        if client.model_name is None:
            raise LMError("Fallback client has no model_name set")
        response = client.completion(message)  # type: ignore[arg-type]
        return response, client.get_usage_summary(), client.model_name

    def _validate_persistent_environment_support(self) -> None:
        """
        Validate that the configured environment type supports persistent mode.

        Persistent mode requires environments to implement:
        - update_handler_address(address): Update LM handler address between calls
        - add_context(payload, index): Add new context for multi-turn conversations
        - get_context_count(): Return the number of loaded contexts

        Currently only 'local' (LocalREPL) supports these methods.

        Raises:
            ValueError: If the environment type does not support persistent mode.
        """
        # Known environments that support persistence
        persistent_supported_environments = {"local"}

        if self.environment_type not in persistent_supported_environments:
            raise ValueError(
                f"persistent=True is not supported for environment type '{self.environment_type}'. "
                f"Persistent mode requires environments that implement update_handler_address(), "
                f"add_context(), and get_context_count(). "
                f"Supported environments: {sorted(persistent_supported_environments)}"
            )

    @staticmethod
    def _env_supports_persistence(env: object) -> bool:
        """Check if an environment instance supports persistent mode methods."""
        return isinstance(env, SupportsPersistence)

    def close(self) -> None:
        """Clean up persistent environment. Call when done with multi-turn conversations."""
        if self._persistent_env is not None:
            cleanup = getattr(self._persistent_env, "cleanup", None)
            if cleanup is None or not callable(cleanup):
                raise SetupRLMError(
                    f"Persistent environment"
                    f" {type(self._persistent_env).__name__}"
                    f" missing callable cleanup()"
                )
            cleanup()
            self._persistent_env = None

    def __enter__(self) -> "RLM":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False
