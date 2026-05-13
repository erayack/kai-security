# Contributing

Thanks for helping improve Kai. This project is early and security-sensitive,
so the best contributions are small, well-scoped, and easy to review.

## Development Setup

Requirements:

- Python 3.12+
- uv
- Foundry, when working with Solidity targets

Install dependencies:

```bash
uv sync --group dev
```

Run checks before opening a pull request:

```bash
make check
```

If your local pytest environment has globally installed plugins, use the same
hermetic test command as CI:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run pytest -q -p pytest_asyncio.plugin
```

## Pull Request Guidelines

- Keep changes focused on one behavior or cleanup area.
- Add or update tests for behavior changes and bug fixes.
- Update README or docs when CLI behavior, configuration, or workflows change.
- Do not commit `.env`, logs, target repositories, generated output, API keys,
  or private vulnerability data.
- Do not include exploit details for live third-party systems unless disclosure
  has been coordinated and authorized.

## Code Style

- Use `uv`, not `pip`, for dependency management.
- Prefer the existing `kai` and `ra` abstractions over new framework code.
- Keep public APIs typed and documented.
- Run `uv run ruff format src tests scripts` before large Python changes.

## Issues

Use GitHub issues for bugs, feature requests, documentation gaps, and design
questions. Report vulnerabilities in Kai itself privately using
[SECURITY.md](SECURITY.md).
