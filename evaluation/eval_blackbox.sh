#!/bin/bash
set -e

REPO_PATH="./testbed/contracts-f3e56d5f/master"

echo "========================================"
echo "Starting evaluation pipeline"
echo "Repo path: $REPO_PATH"
echo "Output dir: ./evaluation_output"
echo "========================================"
echo ""

# Run blackbox and show output
uv run python -m evaluation.cli run \
    --repo-path "$REPO_PATH" \
    --baseline-invariants ./tests/fixtures/invariants_test.json \
    --output-dir ./evaluation_output \
    --num-turns 24

echo ""
echo "========================================"
echo "Listing all generated artifacts:"
echo "========================================"
ls -la ./evaluation_output/

# Find the most recently created synthesized invariants file
SYNTH_FILE=$(ls -t ./evaluation_output/synthesized_invariants_*.json 2>/dev/null | head -1)

# Check if we found a synthesized invariants file
if [ -z "$SYNTH_FILE" ]; then
    echo ""
    echo "ERROR: No synthesized invariants file found in ./evaluation_output/"
    echo "The run command may not have produced any invariants."
    echo ""
    echo "Let's inspect what observations were generated:"
    OBS_FILE=$(ls -t ./evaluation_output/observations_*.json 2>/dev/null | head -1)
    if [ -n "$OBS_FILE" ]; then
        echo "Observations file: $OBS_FILE"
        echo "Contents:"
        cat "$OBS_FILE" | python3 -c 'import json,sys; obs=json.load(sys.stdin); print(f"Total observations: {len(obs)}"); [print(f"  {i+1}. {o.get(\"description\", \"no description\")[:100]}...") for i,o in enumerate(obs)]'
    fi
    echo ""
    echo "Let's inspect the evaluation report:"
    REPORT_FILE=$(ls -t ./evaluation_output/evaluation_report_*.json 2>/dev/null | head -1)
    if [ -n "$REPORT_FILE" ]; then
        echo "Report file: $REPORT_FILE"
        cat "$REPORT_FILE" | python3 -c 'import json,sys; r=json.load(sys.stdin); m=r.get("metrics",{}); print(f"  total_observations: {m.get(\"total_observations\")}"); print(f"  observations_with_synthesis: {m.get(\"observations_with_synthesis\")}"); print(f"  total_synthesized: {m.get(\"total_synthesized\")}")'
    fi
    exit 1
fi

echo ""
echo "========================================"
echo "Found synthesized invariants file: $SYNTH_FILE"
SYNTH_COUNT=$(cat "$SYNTH_FILE" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
echo "Synthesized invariants count: $SYNTH_COUNT"
echo "========================================"

echo "========================================"
echo "Running deduplication"
echo "  Checking $SYNTH_COUNT new synthesized invariants for novelty against 114 baseline invariants"
echo "========================================"
echo ""

# Run deduplication - check NEW synthesized invariants against original baseline
uv run python -m evaluation.cli deduplicate \
    --invariants "$SYNTH_FILE" \
    --baseline ./tests/fixtures/invariants_test.json \
    --output ./evaluation_output/novel_invariants.json \
    --max-concurrent 5

