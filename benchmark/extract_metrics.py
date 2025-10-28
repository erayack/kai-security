#!/usr/bin/env python3
"""
Extract comprehensive metrics for exploit_agent benchmark analysis.
"""
import json
import csv
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Actual costs per 1M tokens from large benchmark requests (with caching effects)
ACTUAL_COST_PER_1M = {
    'anthropic/claude-sonnet-4.5': 3.59,
    'google/gemini-2.5-pro': 0.48,
    'google/gemini-2.5-flash': 0.14,
    'deepseek/deepseek-chat-v3.1': 0.38,
    'openai/gpt-5': 0.47,
    'openai/gpt-4.1': 0.70,
    'openai/gpt-5-codex': 0.52,
    'x-ai/grok-code-fast-1': 0.09,
    'z-ai/glm-4.6': 0.52,
    'moonshotai/kimi-k2-0905': 0.37,
}

# Average tokens per benchmark request (from CSV analysis)
AVG_TOKENS_PER_REQUEST = {
    'anthropic/claude-sonnet-4.5': 101774,
    'google/gemini-2.5-pro': 93602,
    'google/gemini-2.5-flash': 77722,
    'deepseek/deepseek-chat-v3.1': 58337,
    'openai/gpt-5': 131152,
    'openai/gpt-4.1': 98723,
    'openai/gpt-5-codex': 48074,
    'x-ai/grok-code-fast-1': 41318,
    'z-ai/glm-4.6': 51832,
    'moonshotai/kimi-k2-0905': 35548,
}

def _project_root() -> str:
    return str(Path(__file__).resolve().parent.parent)

def calculate_actual_cost(model: str) -> float:
    """Calculate actual cost per request based on observed data"""
    tokens = AVG_TOKENS_PER_REQUEST.get(model, 50000)
    cost_per_1m = ACTUAL_COST_PER_1M.get(model, 0.50)
    return (tokens / 1_000_000) * cost_per_1m

def extract_metrics():
    """Extract comprehensive metrics from all benchmark results"""

    benchmark_dir = os.path.join(_project_root(), 'benchmark_output')

    # Comprehensive metrics storage
    all_metrics = []

    # Per-model aggregations
    model_aggregates = defaultdict(lambda: {
        'total_runs': 0,
        'successful_runs': 0,
        'failed_runs': 0,
        'total_vulns': 0,
        'total_critical': 0,
        'total_high': 0,
        'total_medium': 0,
        'total_low': 0,
        'total_duration': 0,
        'total_cost': 0,
        'runs_by_turn': defaultdict(int),
        'vulns_by_turn': defaultdict(int),
        'cost_by_turn': defaultdict(float),
        'duration_by_turn': defaultdict(float),
        'repos': set()
    })

    # Per-repository aggregations
    repo_aggregates = defaultdict(lambda: {
        'total_runs': 0,
        'successful_runs': 0,
        'total_vulns': 0,
        'best_model': None,
        'best_model_vulns': 0
    })

    print("Extracting metrics from benchmark results...")

    for repo_dir in sorted(os.listdir(benchmark_dir)):
        if '_turns256' in repo_dir:
            continue

        repo_path = os.path.join(benchmark_dir, repo_dir)
        results_file = os.path.join(repo_path, 'benchmark_results.json')

        if not os.path.isfile(results_file):
            continue

        # Extract turn count and repo name
        if '_turns' in repo_dir:
            parts = repo_dir.rsplit('_turns', 1)
            repo_name = parts[0]
            turn_count = int(parts[1])
        else:
            repo_name = repo_dir
            turn_count = 20  # Original benchmark

        with open(results_file, 'r') as f:
            results = json.load(f)

        for result in results:
            model = result.get('model')
            status = result.get('status')

            # Calculate actual cost
            actual_cost = calculate_actual_cost(model) if status == 'success' else 0

            # Basic metrics
            duration = result.get('duration_seconds', 0)
            vulns = result.get('vulnerabilities', {})
            total_vulns = vulns.get('total', 0)

            # Calculate per-turn metrics
            avg_duration_per_turn = duration / turn_count if turn_count > 0 else 0
            vulns_per_turn = total_vulns / turn_count if turn_count > 0 else 0
            cost_per_turn = actual_cost / turn_count if turn_count > 0 else 0

            # Store comprehensive metrics
            metric = {
                'model': model,
                'repository': repo_name,
                'turn_count': turn_count,
                'status': status,
                'total_duration_seconds': duration,
                'avg_duration_per_turn': avg_duration_per_turn,
                'total_vulnerabilities': total_vulns,
                'critical_vulns': vulns.get('critical', 0),
                'high_vulns': vulns.get('high', 0),
                'medium_vulns': vulns.get('medium', 0),
                'low_vulns': vulns.get('low', 0),
                'info_vulns': vulns.get('info', 0),
                'vulns_per_turn': vulns_per_turn,
                'actual_cost_usd': actual_cost,
                'cost_per_turn': cost_per_turn,
                'cost_per_vuln': actual_cost / total_vulns if total_vulns > 0 else None,
                'vulns_per_dollar': total_vulns / actual_cost if actual_cost > 0 else None,
                'timestamp': result.get('timestamp', 'unknown'),
                'error': result.get('error', '') if status == 'failed' else ''
            }

            all_metrics.append(metric)

            # Update aggregations
            if status == 'success':
                agg = model_aggregates[model]
                agg['successful_runs'] += 1
                agg['total_vulns'] += total_vulns
                agg['total_critical'] += vulns.get('critical', 0)
                agg['total_high'] += vulns.get('high', 0)
                agg['total_medium'] += vulns.get('medium', 0)
                agg['total_low'] += vulns.get('low', 0)
                agg['total_duration'] += duration
                agg['total_cost'] += actual_cost
                agg['runs_by_turn'][turn_count] += 1
                agg['vulns_by_turn'][turn_count] += total_vulns
                agg['cost_by_turn'][turn_count] += actual_cost
                agg['duration_by_turn'][turn_count] += duration
                agg['repos'].add(repo_name)

                # Repository aggregation
                repo_agg = repo_aggregates[f"{repo_name}_turns{turn_count}"]
                repo_agg['successful_runs'] += 1
                repo_agg['total_vulns'] += total_vulns
                if total_vulns > repo_agg['best_model_vulns']:
                    repo_agg['best_model'] = model
                    repo_agg['best_model_vulns'] = total_vulns
            else:
                model_aggregates[model]['failed_runs'] += 1

            model_aggregates[model]['total_runs'] += 1
            repo_aggregates[f"{repo_name}_turns{turn_count}"]['total_runs'] += 1

    return all_metrics, model_aggregates, repo_aggregates

def save_metrics_to_csv(metrics, filename='benchmark_metrics.csv'):
    """Save metrics to CSV"""
    if not metrics:
        return

    keys = metrics[0].keys()

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(metrics)

    print(f"✓ Saved {len(metrics)} metric rows to {filename}")

def save_aggregates_to_json(model_aggs, repo_aggs, filename='benchmark_aggregates.json'):
    """Save aggregated metrics to JSON"""

    # Convert sets to lists for JSON serialization
    model_data = {}
    for model, agg in model_aggs.items():
        model_data[model] = {
            'total_runs': agg['total_runs'],
            'successful_runs': agg['successful_runs'],
            'failed_runs': agg['failed_runs'],
            'success_rate': agg['successful_runs'] / agg['total_runs'] if agg['total_runs'] > 0 else 0,
            'total_vulnerabilities': agg['total_vulns'],
            'avg_vulns_per_run': agg['total_vulns'] / agg['successful_runs'] if agg['successful_runs'] > 0 else 0,
            'critical': agg['total_critical'],
            'high': agg['total_high'],
            'medium': agg['total_medium'],
            'low': agg['total_low'],
            'avg_duration': agg['total_duration'] / agg['successful_runs'] if agg['successful_runs'] > 0 else 0,
            'total_cost': agg['total_cost'],
            'avg_cost_per_run': agg['total_cost'] / agg['successful_runs'] if agg['successful_runs'] > 0 else 0,
            'cost_per_vuln': agg['total_cost'] / agg['total_vulns'] if agg['total_vulns'] > 0 else None,
            'repositories_tested': list(agg['repos']),
            'performance_by_turn_count': {
                str(turns): {
                    'runs': count,
                    'avg_vulns': agg['vulns_by_turn'][turns] / count if count > 0 else 0,
                    'avg_cost': agg['cost_by_turn'][turns] / count if count > 0 else 0,
                    'avg_duration': agg['duration_by_turn'][turns] / count if count > 0 else 0
                }
                for turns, count in agg['runs_by_turn'].items()
            }
        }

    output = {
        'generated_at': datetime.now().isoformat(),
        'total_benchmark_runs': sum(m['total_runs'] for m in model_aggs.values()),
        'total_successful_runs': sum(m['successful_runs'] for m in model_aggs.values()),
        'models': model_data,
        'repositories': dict(repo_aggs)
    }

    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"✓ Saved aggregated metrics to {filename}")

def generate_summary_report(model_aggs):
    """Generate human-readable summary report"""

    print("\n" + "="*100)
    print("COMPREHENSIVE BENCHMARK SUMMARY")
    print("="*100)

    # Overall stats
    total_runs = sum(m['total_runs'] for m in model_aggs.values())
    total_success = sum(m['successful_runs'] for m in model_aggs.values())
    total_vulns = sum(m['total_vulns'] for m in model_aggs.values())
    total_cost = sum(m['total_cost'] for m in model_aggs.values())

    print(f"\nTotal benchmark runs: {total_runs}")
    print(f"Successful runs: {total_success} ({total_success*100//total_runs}%)")
    print(f"Total vulnerabilities found: {total_vulns}")
    print(f"Total cost: ${total_cost:.2f}")

    # Top performers by different metrics
    print("\n" + "="*100)
    print("TOP PERFORMERS")
    print("="*100)

    # Most cost-effective
    print("\n## Most Cost-Effective ($ per vulnerability):")
    cost_effective = sorted(
        [(m, agg['total_cost']/agg['total_vulns']) for m, agg in model_aggs.items() if agg['total_vulns'] > 0],
        key=lambda x: x[1]
    )
    for i, (model, cpv) in enumerate(cost_effective[:5], 1):
        agg = model_aggs[model]
        print(f"  {i}. {model:<40} ${cpv:.4f}/vuln ({agg['total_vulns']} vulns, ${agg['total_cost']:.2f})")

    # Most thorough
    print("\n## Most Thorough (total vulnerabilities found):")
    thorough = sorted(model_aggs.items(), key=lambda x: x[1]['total_vulns'], reverse=True)
    for i, (model, agg) in enumerate(thorough[:5], 1):
        avg = agg['total_vulns'] / agg['successful_runs'] if agg['successful_runs'] > 0 else 0
        print(f"  {i}. {model:<40} {agg['total_vulns']} total ({avg:.1f} avg/run)")

    # Fastest
    print("\n## Fastest (average time per run):")
    fastest = sorted(
        [(m, agg['total_duration']/agg['successful_runs']) for m, agg in model_aggs.items() if agg['successful_runs'] > 0],
        key=lambda x: x[1]
    )
    for i, (model, avg_time) in enumerate(fastest[:5], 1):
        agg = model_aggs[model]
        print(f"  {i}. {model:<40} {avg_time:.0f}s avg ({agg['total_vulns']} vulns)")

    # Best value (vulns per dollar)
    print("\n## Best Value (vulnerabilities per dollar):")
    value = sorted(
        [(m, agg['total_vulns']/agg['total_cost']) for m, agg in model_aggs.items() if agg['total_cost'] > 0],
        key=lambda x: x[1],
        reverse=True
    )
    for i, (model, vpd) in enumerate(value[:5], 1):
        agg = model_aggs[model]
        print(f"  {i}. {model:<40} {vpd:.1f} vulns/$")

    # Most reliable
    print("\n## Most Reliable (success rate):")
    reliable = sorted(
        [(m, agg['successful_runs']/agg['total_runs']) for m, agg in model_aggs.items() if agg['total_runs'] > 0],
        key=lambda x: x[1],
        reverse=True
    )
    for i, (model, success_rate) in enumerate(reliable[:5], 1):
        agg = model_aggs[model]
        print(f"  {i}. {model:<40} {success_rate*100:.0f}% ({agg['successful_runs']}/{agg['total_runs']})")

def main():
    print("="*100)
    print("EXTRACTING COMPREHENSIVE EXPLOIT AGENT METRICS")
    print("="*100)
    print()

    # Extract all metrics
    metrics, model_aggs, repo_aggs = extract_metrics()

    # Save to files in benchmark directory
    benchmark_dir = os.path.join(_project_root(), 'benchmark')
    save_metrics_to_csv(metrics, os.path.join(benchmark_dir, 'benchmark_metrics.csv'))
    save_aggregates_to_json(model_aggs, repo_aggs, os.path.join(benchmark_dir, 'benchmark_aggregates.json'))

    # Generate summary report
    generate_summary_report(model_aggs)

    print("\n" + "="*100)
    print("FILES GENERATED:")
    print("="*100)
    print("  1. benchmark_metrics.csv - Detailed per-run metrics")
    print("  2. benchmark_aggregates.json - Aggregated statistics")
    print("="*100)

if __name__ == "__main__":
    main()
