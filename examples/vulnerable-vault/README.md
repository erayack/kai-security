# vulnerable-vault

A tiny, self-contained, **intentionally vulnerable** Solidity project — a
target you can point `kai audit` at to see the whole pipeline run end to end
without a private repo or a large API spend.

> ⚠️ Intentionally insecure. Do not deploy. For authorized demonstration only.

## Planted bugs

| # | Bug | Location | Expected category |
|---|-----|----------|-------------------|
| 1 | **Reentrancy** — external call before the balance is zeroed, no guard | `src/Vault.sol` · `withdraw()` | `active_exploit` |
| 2 | **Unchecked ERC-20 return** — `transfer()` boolean ignored | `src/Vault.sol` · `sweepToken()` | `active_exploit` |

## Run it

```bash
# From the kai-security repo root
uv run kai audit --repo-path examples/vulnerable-vault \
  --threat-context examples/vulnerable-vault/threat_context.yaml --verbose
```

Then look at the results:

```bash
# Interactive HTML (findings + the agent's reasoning trace)
uv run kai view output/state/<run_id> --open

# Or a Markdown report (stdout), or a styled HTML document
uv run kai report output/state/<run_id>
uv run kai report output/state/<run_id> --format html -o report.html
```

`<run_id>` is printed during the run and is the directory name under
`output/state/`.

## What to expect

Kai should surface the reentrancy in `withdraw()` as a confirmed
`active_exploit` (typically the highest-CVSS finding, with a working PoC and a
suggested patch that moves the balance update before the external call), and
flag the unchecked `transfer()` return in `sweepToken()`. Exact wording, CVSS
scores, and ordering depend on the models configured for the run.
