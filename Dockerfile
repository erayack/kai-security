# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the Railway parallel benchmark worker.
#
# Stage 1 (builder): pin uv + git, resolve the lockfile, and install
# project deps into /app/.venv. The Railway `railway` extra pulls in
# psycopg[binary] for the Postgres-backed task store.
#
# Stage 2 (runtime): a slim python:3.12-slim layer that copies just
# /app/.venv and the source tree. Application secrets (OPENROUTER_API_KEY,
# DATABASE_URL, ...) are injected as Railway env vars at runtime --
# .env is deliberately NOT copied; see .dockerignore.

ARG PYTHON_IMAGE=python:3.12-slim

# ---------- builder ----------
FROM ${PYTHON_IMAGE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv via the official Astral installer.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv \
    && mv /root/.local/bin/uvx /usr/local/bin/uvx

WORKDIR /app

# Copy only the lockfile + manifest first so dependency layers cache
# independently of source changes.
COPY pyproject.toml uv.lock README.md ./

# Install runtime deps (no dev tools) plus the railway extra for psycopg.
# `--no-install-project` is required because src/ is not in the build
# context yet — installing the local `kai` package now would fail with
# "Expected a Python module at: src/kai/__init__.py".
RUN uv sync --frozen --no-dev --no-install-project --extra railway

# Copy the source tree last so editable installs can resolve.
COPY src ./src
COPY evaluation ./evaluation

# Re-run uv sync to register the local `kai` project in the venv.
RUN uv sync --frozen --no-dev --extra railway

# ---------- runtime ----------
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/app/.venv/bin:$PATH \
    VIRTUAL_ENV=/app/.venv \
    KAI_BACKEND=openrouter \
    KAI_LOG_STRUCTURED=1 \
    BENCHMARK_OUTPUT_ROOT=/app/output/bench

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the pre-built virtualenv and the source tree from the builder.
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src
COPY --from=builder /app/evaluation /app/evaluation
COPY --from=builder /app/pyproject.toml /app/pyproject.toml

# Pre-create the output root so SIGTERM during the first task doesn't
# trip over a missing dir on the way out.
RUN mkdir -p /app/output/bench

# Clone the bountybench task shell so workers can run the bountybench
# adapter out of the box. Each system's `codebase/` is itself a git
# submodule which the adapter initialises lazily per task (some
# codebases are >1 GB; baking them all would blow up the image).
ARG BOUNTYTASKS_REF=main
RUN git clone --depth 1 --branch "${BOUNTYTASKS_REF}" \
        https://github.com/bountybench/bountytasks.git /app/bountytasks \
    && git -C /app/bountytasks remote set-branches origin "${BOUNTYTASKS_REF}"
ENV BOUNTYBENCH_ROOT=/app/bountytasks

# Clone the EVMbench frontier-evals subtree so the evmbench adapter can
# read audits/<id>/config.yaml. Each audit's source repo lives at
# evmbench-org/<id> on GitHub and the adapter clones it lazily on first
# use (with a per-worker on-disk cache).
ARG FRONTIER_EVALS_REF=main
RUN git clone --depth 1 --branch "${FRONTIER_EVALS_REF}" \
        https://github.com/openai/frontier-evals.git /app/frontier-evals \
    && git -C /app/frontier-evals remote set-branches origin "${FRONTIER_EVALS_REF}"
ENV EVMBENCH_FRONTIER_EVALS_ROOT=/app/frontier-evals/project/evmbench

# Liveness check the platform can use to detect stuck containers.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import kai, evaluation; print('ok')" || exit 1

# tini reaps zombie subprocesses (the worker shells out to kai.main).
ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "evaluation.worker"]
