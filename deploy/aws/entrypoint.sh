#!/bin/bash
set -e

echo "=========================================="
echo "Kai Security Analysis - AWS Deployment"
echo "=========================================="
echo "Start time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# Verify environment
if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "ERROR: OPENROUTER_API_KEY environment variable is required"
    exit 1
fi

# Show configuration
echo "Configuration:"
echo "  - REPOS: ${REPOS:-all cantina repos}"
echo "  - MAIN_MODEL: ${MAIN_MODEL:-anthropic/claude-opus-4.5}"
echo "  - COMPILE_TIMEOUT: ${COMPILE_TIMEOUT:-600}s"
echo "  - TEST_TIMEOUT: ${TEST_TIMEOUT:-300}s"
echo ""

# Build command
CMD="python scripts/batch_cantina_runner.py"

# Add optional arguments
if [ -n "$REPOS" ]; then
    # Convert comma-separated repos to multiple --repo flags or use limit
    CMD="$CMD --limit 1"  # Will be overridden by actual repo selection in script
fi

if [ -n "$LIMIT" ]; then
    CMD="$CMD --limit $LIMIT"
fi

if [ -n "$MAIN_MODEL" ]; then
    CMD="$CMD --main-model $MAIN_MODEL"
fi

if [ -n "$VERIFIER_MODEL" ]; then
    CMD="$CMD --verifier-model $VERIFIER_MODEL"
fi

if [ -n "$COMPILE_TIMEOUT" ]; then
    CMD="$CMD --compile-timeout $COMPILE_TIMEOUT"
fi

if [ -n "$TEST_TIMEOUT" ]; then
    CMD="$CMD --test-timeout $TEST_TIMEOUT"
fi

# Always save to DB if MONGO_URI is set
if [ -n "$MONGO_URI" ]; then
    CMD="$CMD --save-to-db"
fi

echo "Running: $CMD"
echo "=========================================="
echo ""

# Run the command
exec $CMD
