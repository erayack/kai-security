import time
from contextlib import contextmanager
from typing import Any

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
from ra.exceptions import LMError, SetupRLMError
from ra.logger import RecursiveAgentLogger, VerbosePrinter
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
        logger: RecursiveAgentLogger | None = None,
        verbose: bool = False,
        log_file: str = "",
        persistent: bool = False,
        name: str = "",
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

        self.depth = depth
        self.max_depth = max_depth
        self.max_iterations = max_iterations
        self.system_prompt = (
            custom_system_prompt if custom_system_prompt else RLM_SYSTEM_PROMPT
        )
        self.name = name
        self.logger = logger
        self.verbose = VerbosePrinter(
            enabled=verbose,
            name=name,
            depth=depth,
            log_file=log_file,
        )

        # Persistence support
        self.persistent = persistent
        self._persistent_env: SupportsPersistence | None = None

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

            for i in range(self.max_iterations):
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

                iteration: RLMIteration = self._completion_turn(
                    prompt=current_prompt,
                    lm_handler=lm_handler,
                    environment=environment,
                    iteration_num=i + 1,
                )

                # Collect child usage from spawn calls
                for cb in iteration.code_blocks:
                    for call in cb.result.rlm_calls:
                        child_usage = child_usage.merge(call.usage_summary)

                # Check if RLM is done and has a final answer.
                final_answer = find_final_answer(
                    iteration.response, environment=environment
                )
                iteration.final_answer = final_answer

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

            # Default behavior: we run out of iterations, provide one final answer
            time_end = time.perf_counter()
            final_answer = self._default_answer(
                message_history, lm_handler, environment=environment
            )
            usage = lm_handler.get_usage_summary().merge(child_usage)
            self.verbose.print_final_answer(final_answer)
            self.verbose.print_summary(
                self.max_iterations, time_end - time_start, usage.to_dict()
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
        prompt: str | dict[str, Any],
        lm_handler: LMHandler,
        environment: BaseEnv,
        iteration_num: int = 0,
    ) -> RLMIteration:
        """
        Perform a single iteration of the RLM, including prompting the model
        and code execution + tool execution.
        """
        iter_start = time.perf_counter()
        response = lm_handler.completion(prompt)  # type: ignore[arg-type]
        llm_time = time.perf_counter() - iter_start

        # Print LLM response immediately
        self.verbose.print_iteration_start(iteration_num)
        self.verbose.print_completion(response, llm_time)

        code_block_strs = find_code_blocks(response)
        code_blocks = []

        for code_block_str in code_block_strs:
            self.verbose.print_pre_execution(code_block_str)
            code_result: REPLResult = environment.execute_code(code_block_str)
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
        return RLMIteration(
            prompt=prompt,
            response=response,
            code_blocks=code_blocks,
            iteration_time=iteration_time,
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
        response = lm_handler.completion(current_prompt)

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
