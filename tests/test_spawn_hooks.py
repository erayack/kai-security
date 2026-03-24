"""Tests for spawn hook wrappers."""

from __future__ import annotations

from kai.definitions.exploit.spawn_hooks import (
    make_threat_context_spawn_wrapper,
)


def _echo_spawn(**kwargs: object) -> str:
    """Fake spawn function that returns kwargs as string."""
    return repr(kwargs)


class TestThreatContextWrapper:
    """Test make_threat_context_spawn_wrapper."""

    def test_injects_threat_context(self) -> None:
        tc = {"deployment_type": "web-app", "environment": "server"}
        factory = make_threat_context_spawn_wrapper(tc)
        wrapped = factory(_echo_spawn)
        result = wrapped(query="test")
        assert "threat_context" in result
        assert "web-app" in result

    def test_does_not_override_explicit(self) -> None:
        tc = {"deployment_type": "web-app"}
        factory = make_threat_context_spawn_wrapper(tc)
        wrapped = factory(_echo_spawn)
        explicit = {"deployment_type": "cli-tool"}
        result = wrapped(query="test", threat_context=explicit)
        assert "cli-tool" in result
        assert "web-app" not in result

    def test_factory_returns_factory(self) -> None:
        tc = {"deployment_type": "smart-contract"}
        factory = make_threat_context_spawn_wrapper(tc)
        # factory(spawn_fn) should return a callable
        wrapped = factory(_echo_spawn)
        assert callable(wrapped)

    def test_chained_with_another_wrapper(self) -> None:
        """Verify threat_context wrapper composes with other wrappers."""
        tc = {"deployment_type": "web-app"}
        tc_factory = make_threat_context_spawn_wrapper(tc)

        def other_factory(
            original: object,
        ) -> object:
            """Another wrapper that adds extra_key."""

            def wrapped(**kwargs: object) -> str:
                kwargs["extra_key"] = "extra_value"
                return original(**kwargs)  # type: ignore[operator]

            return wrapped

        # Compose: tc_factory wraps other_factory's output
        chained_fn = tc_factory(other_factory(_echo_spawn))
        result = chained_fn(query="test")
        assert "threat_context" in result
        assert "extra_key" in result
