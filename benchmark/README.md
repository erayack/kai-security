# Benchmark Results

This directory contains all benchmarking scripts, results, and analysis for evaluating LLM models on vulnerability detection.

## Directory Structure

```
benchmarks/
├── README.md                           # This file
├── benchmark_models.py                 # Main benchmarking script
├── resume_benchmark.py                 # Resume failed benchmarks
├── analyze_actual_costs.py             # Cost analysis with OpenRouter data
├── extract_comprehensive_metrics.py    # Extract detailed metrics
├── BENCHMARK_INTERPRETATION.md         # Complete analysis & recommendations
├── benchmark_metrics.csv               # Per-run detailed metrics (160 runs)
├── benchmark_aggregates.json           # Aggregated statistics by model
├── actual_costs_analysis.json          # Cost analysis results
├── openrouter_activity_2025-10-25.csv  # Actual OpenRouter API usage
└── benchmark_output/                   # Raw results by repository & turn count
```

## Quick Start

### Run a New Benchmark

```bash
# Using make (recommended - runs from project root)
make benchmark

# Or run directly from benchmark directory
cd benchmark
python3 benchmark_models.py
```

### Resume Failed Benchmarks

```bash
# Using make (recommended)
make resume-benchmark

# Or run directly with custom options
cd benchmark
python3 resume_benchmarks.py --exclude-turns 128 256
```

### Analyze Results

```bash
# Extract metrics from benchmark results
make extract-metrics

# Comprehensive cost analysis with actual OpenRouter data
make analyse-costs

# Or run directly from benchmark directory
cd benchmark
python3 extract_metrics.py
python3 analyse_costs.py
```

## Key Findings

**Total Benchmarks:** 160 runs (79 successful apple-to-apple comparisons)
**Total Cost:** $418.58
**Total Vulnerabilities:** 1,284 found across all models

### Top 3 Models (32 & 64 turns)

1. **moonshotai/kimi-k2-0905** 🏆
   - Cost: $0.023/vuln (cheapest)
   - ROI: 44 vulnerabilities per dollar
   - Severity: 73% critical/high
   - **Recommendation:** Best for most users

2. **openai/gpt-5** 🥇
   - Cost: $0.087/vuln
   - Found: 317 vulnerabilities (most thorough)
   - Represents 33% of all vulnerabilities
   - **Recommendation:** When quality is paramount

3. **deepseek/deepseek-chat-v3.1** 🥉
   - Cost: $0.058/vuln
   - Found: 146 vulnerabilities
   - ROI: 17 vulnerabilities per dollar
   - **Recommendation:** Balanced performance

### Models to Avoid

- ❌ **anthropic/claude-sonnet-4.5** - $2.60/vuln (114x more expensive than Kimi, consumed 78% of budget)
- ❌ **openai/gpt-4.1** - Poor efficiency, only 30 vulnerabilities found
- ❌ **openai/gpt-5-codex** - Very slow, only 18 vulnerabilities found

## Benchmark Configuration

**Models Tested:** 10 (Anthropic, OpenAI, Google, DeepSeek, Moonshot, X.AI, Z.AI)
**Repositories:** 6 real-world smart contract codebases
**Turn Counts:** 20, 32, 64, 128
**Best Turn Count:** 64 turns (optimal for most models)

## Files Description

### Scripts

- **benchmark_models.py** - Main script that runs all models in parallel across repositories
- **resume_benchmark.py** - Identifies failed runs and re-runs only those (saves money)
- **analyze_actual_costs.py** - Matches benchmark results with actual OpenRouter API usage for accurate cost analysis
- **extract_comprehensive_metrics.py** - Generates CSV and JSON metrics from raw results

### Results

- **BENCHMARK_INTERPRETATION.md** - Complete analysis with recommendations by use case
- **benchmark_metrics.csv** - 160 rows with per-run metrics (cost, duration, vulnerabilities by severity)
- **benchmark_aggregates.json** - Per-model aggregations and statistics
- **actual_costs_analysis.json** - Cost analysis combining benchmark results with OpenRouter data

### Data

- **openrouter_activity_2025-10-25.csv** - 7,077 rows of actual API calls from OpenRouter
- **benchmark_output/** - Raw JSON results organized by repository and turn count

## Methodology

1. **Parallel Execution:** Models run simultaneously to save time
2. **Repository Isolation:** Each model gets its own repository clone to avoid race conditions
3. **Cost Tracking:** Estimated costs during run, verified against actual OpenRouter usage
4. **Resume Capability:** Failed runs can be resumed without re-running successful ones
5. **Apple-to-Apple:** Final analysis focuses on 32 & 64 turn runs where all models have equal coverage

## Interpreting Results

See `BENCHMARK_INTERPRETATION.md` for:
- Detailed model comparisons
- Cost vs quality analysis
- Recommendations by use case
- Turn count optimization
- Efficiency scores

## Usage Examples

### Run Complete Benchmark Suite

```bash
# Run all benchmarks from project root
make benchmark
```

### Resume Failed Benchmarks (32 & 64 turns only)

```bash
# Resume from project root with default settings
make resume-benchmark

# Or customize excluded turn counts
cd benchmark
python3 resume_benchmarks.py --exclude-turns 128 256
```

### Generate Fresh Metrics

```bash
# Extract metrics using make
make extract-metrics

# Analyze costs with OpenRouter data
make analyse-costs
```

### Advanced: Benchmark a Specific Repository (Python)

```python
from benchmark_models import run_finder_for_model

result = run_finder_for_model(
    model_name="moonshotai/kimi-k2-0905",
    repo_url="https://github.com/example/repo",
    num_turns=64
)
```

---

*For questions or issues with benchmarking, refer to the main repository README or open an issue.*
