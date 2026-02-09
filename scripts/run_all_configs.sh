#!/bin/bash
# Run batch_cantina_runner.py with each model config sequentially.
# Cleans up workspaces and caches between runs.
# Each run gets its own timestamped output directory in output/cantina_batch/.
#
# Usage:
#   tmux new -s benchmark
#   bash scripts/run_all_configs.sh
#
# Requires OPENROUTER_API_KEY and optionally MONGO_URI to be set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Activate venv
source .venv/bin/activate

COMMON_ARGS="--compile-timeout 600 --save-to-db --save-rollouts"

cleanup() {
    echo ""
    echo "=== Cleaning up between runs ==="
    rm -rf "$PROJECT_ROOT/temp_clones"/*
    rm -rf "$PROJECT_ROOT/kai_workspaces"/*
    # Clear forge cache to free memory/disk
    if command -v forge &> /dev/null; then
        forge cache clean 2>/dev/null || true
    fi
    sync
    echo "Cleanup done. Disk: $(df -h / | tail -1 | awk '{print $4}') free"
    echo ""
}

echo "============================================================"
echo "MULTI-CONFIG BENCHMARK RUNNER"
echo "============================================================"
echo "5 configs × 17 repos = 85 runs"
echo "Output: output/cantina_batch/<timestamp>/ per config"
echo "============================================================"
echo ""

# ==================== CONFIG 1: OpenAI ====================
echo ">>> CONFIG 1/5: OpenAI (gpt-5.2-codex)"
python scripts/batch_cantina_runner.py $COMMON_ARGS \
    --main-model openai/gpt-5.2-codex \
    --setup-model openai/gpt-5.2-codex \
    --verifier-model openai/gpt-5.2-codex \
    --invariant-model openai/gpt-5.2-codex \
    --fixer-model openai/gpt-5.2-codex \
    --dedupe-model openai/gpt-5.1-codex \
    --fallback-model openai/gpt-5.1-codex

cleanup

# ==================== CONFIG 2: Google/Deepmind ====================
echo ">>> CONFIG 2/5: Google (gemini-3-pro-preview)"
python scripts/batch_cantina_runner.py $COMMON_ARGS \
    --main-model google/gemini-3-pro-preview \
    --setup-model google/gemini-3-pro-preview \
    --verifier-model google/gemini-3-pro-preview \
    --invariant-model google/gemini-3-pro-preview \
    --fixer-model google/gemini-3-pro-preview \
    --dedupe-model google/gemini-3-flash-preview \
    --fallback-model google/gemini-3-flash-preview

cleanup

# ==================== CONFIG 3: Anthropic ====================
echo ">>> CONFIG 3/5: Anthropic (claude-opus-4.6)"
python scripts/batch_cantina_runner.py $COMMON_ARGS \
    --main-model anthropic/claude-opus-4.6 \
    --setup-model anthropic/claude-opus-4.6 \
    --verifier-model anthropic/claude-opus-4.6 \
    --invariant-model anthropic/claude-opus-4.6 \
    --fixer-model anthropic/claude-sonnet-4.5 \
    --dedupe-model anthropic/claude-haiku-4.5 \
    --fallback-model anthropic/claude-sonnet-4.5

cleanup

# ==================== CONFIG 4: Moonshot ====================
echo ">>> CONFIG 4/5: Moonshot (kimi-k2.5)"
python scripts/batch_cantina_runner.py $COMMON_ARGS \
    --main-model moonshotai/kimi-k2.5 \
    --setup-model moonshotai/kimi-k2.5 \
    --verifier-model moonshotai/kimi-k2.5 \
    --invariant-model moonshotai/kimi-k2.5 \
    --fixer-model moonshotai/kimi-k2.5 \
    --dedupe-model moonshotai/kimi-k2-0905 \
    --fallback-model moonshotai/kimi-k2-0905

cleanup

# ==================== CONFIG 5: XAI ====================
echo ">>> CONFIG 5/5: XAI (grok-4.1-fast)"
python scripts/batch_cantina_runner.py $COMMON_ARGS \
    --main-model x-ai/grok-4.1-fast \
    --setup-model x-ai/grok-4.1-fast \
    --verifier-model x-ai/grok-4.1-fast \
    --invariant-model x-ai/grok-4.1-fast \
    --fixer-model x-ai/grok-4.1-fast \
    --dedupe-model x-ai/grok-4-fast \
    --fallback-model x-ai/grok-4-fast

echo ""
echo "============================================================"
echo "ALL 5 CONFIGS COMPLETE"
echo "============================================================"
echo "Results in: output/cantina_batch/"
echo "============================================================"
