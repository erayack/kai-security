# Open Source Hygiene Checklist

Use this before making the repository public.

## Must Do Before Publishing

- Run a secret scan across the full git history and working tree.
- Verify `.env`, logs, generated output, target repositories, and private
  vulnerability reports are not tracked.
- Confirm `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and
  `CODE_OF_CONDUCT.md` match the project's legal and community preferences.
- Replace placeholder disclosure contacts in `SECURITY.md` if needed.
- Run `make check` from a clean clone.
- Confirm CI passes on the default branch.

## Strongly Recommended

- Review ignored local directories such as `output/`, `incident_logs/`, and
  `master/` before publishing.
- Keep `uv.lock` tracked for reproducible installs.
- Tag the first public release after the README, CLI, and CI agree.
- Add examples that do not require private repositories or large API spend.

## Security-Sensitive Review

- Make sure examples only target intentionally vulnerable local projects or
  repositories you have permission to analyze.
- Do not publish working exploit details for live third-party systems unless
  disclosure is complete.
- Document when users should prefer containers, VMs, or disposable CI workers
  over the default local REPL.
