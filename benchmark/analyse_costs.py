#!/usr/bin/env python3
"""
Comprehensive cost analysis using actual OpenRouter CSV data
Matches API calls with benchmark results to calculate:
- Actual cost per model (including failed runs)
- Cost per turn
- Cost per vulnerability
- Duration analysis
- Turn count efficiency comparison
"""

import csv
import json
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Model name mapping (OpenRouter format -> benchmark format)
MODEL_MAPPING = {
    'anthropic/claude-4.5-sonnet-20250929': 'anthropic/claude-sonnet-4.5',
    'anthropic/claude-sonnet-4.5': 'anthropic/claude-sonnet-4.5',
    'google/gemini-2.5-pro': 'google/gemini-2.5-pro',
    'google/gemini-2.5-flash': 'google/gemini-2.5-flash',
    'google/gemini-2.5-flash-preview-09-2025': 'google/gemini-2.5-flash',
    'openai/gpt-5-2025-08-07': 'openai/gpt-5',
    'openai/gpt-5': 'openai/gpt-5',
    'openai/gpt-4.1': 'openai/gpt-4.1',
    'openai/gpt-5-codex': 'openai/gpt-5-codex',
    'deepseek/deepseek-chat-v3.1': 'deepseek/deepseek-chat-v3.1',
    'moonshotai/kimi-k2-0905': 'moonshotai/kimi-k2-0905',
    'x-ai/grok-code-fast-1': 'x-ai/grok-code-fast-1',
    'z-ai/glm-4.6': 'z-ai/glm-4.6',
}

def _project_root() -> str:
    return str(Path(__file__).resolve().parent.parent)

def parse_openrouter_csv(csv_path):
    """Parse OpenRouter activity CSV and aggregate by model"""
    model_costs = defaultdict(lambda: {
        'total_cost': 0.0,
        'total_calls': 0,
        'total_tokens_prompt': 0,
        'total_tokens_completion': 0,
        'total_generation_time_ms': 0,
        'cache_savings': 0.0
    })

    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            model_slug = row['model_permaslug']

            # Map to benchmark model name
            if model_slug not in MODEL_MAPPING:
                continue

            model = MODEL_MAPPING[model_slug]

            cost = float(row['cost_total']) if row['cost_total'] else 0.0
            cache_cost = float(row['cost_cache']) if row['cost_cache'] else 0.0
            tokens_prompt = int(row['tokens_prompt']) if row['tokens_prompt'] else 0
            tokens_completion = int(row['tokens_completion']) if row['tokens_completion'] else 0
            gen_time = int(row['generation_time_ms']) if row['generation_time_ms'] else 0

            model_costs[model]['total_cost'] += cost
            model_costs[model]['total_calls'] += 1
            model_costs[model]['total_tokens_prompt'] += tokens_prompt
            model_costs[model]['total_tokens_completion'] += tokens_completion
            model_costs[model]['total_generation_time_ms'] += gen_time
            model_costs[model]['cache_savings'] += abs(cache_cost)  # negative values

    return model_costs

def parse_benchmark_results(metrics_csv_path):
    """Parse benchmark metrics CSV"""
    benchmark_data = defaultdict(lambda: defaultdict(list))

    with open(metrics_csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            model = row['model']
            turn_count = row['turn_count']
            status = row['status']

            data = {
                'repository': row['repository'],
                'turn_count': int(turn_count),
                'status': status,
                'total_vulnerabilities': int(row['total_vulnerabilities']),
                'critical': int(row['critical_vulns']),
                'high': int(row['high_vulns']),
                'medium': int(row['medium_vulns']),
                'low': int(row['low_vulns']),
                'duration_seconds': float(row['total_duration_seconds']),
                'estimated_cost': float(row['actual_cost_usd']) if row['actual_cost_usd'] else 0.0
            }

            benchmark_data[model][turn_count].append(data)

    return benchmark_data

def calculate_comprehensive_metrics(openrouter_costs, benchmark_data, turn_filters=None):
    """Calculate comprehensive metrics combining actual costs with benchmark results"""

    results = {}

    for model in benchmark_data.keys():
        if model not in openrouter_costs:
            continue

        or_data = openrouter_costs[model]

        # Aggregate benchmark data
        total_runs = 0
        successful_runs = 0
        failed_runs = 0
        total_vulns = 0
        total_duration = 0

        by_turn = defaultdict(lambda: {
            'runs': 0,
            'successful': 0,
            'failed': 0,
            'vulns': 0,
            'duration': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        })

        for turn_count, runs in benchmark_data[model].items():
            if turn_filters and turn_count not in turn_filters:
                continue

            for run in runs:
                total_runs += 1
                total_duration += run['duration_seconds']
                by_turn[turn_count]['runs'] += 1
                by_turn[turn_count]['duration'] += run['duration_seconds']

                if run['status'] == 'success':
                    successful_runs += 1
                    total_vulns += run['total_vulnerabilities']
                    by_turn[turn_count]['successful'] += 1
                    by_turn[turn_count]['vulns'] += run['total_vulnerabilities']
                    by_turn[turn_count]['critical'] += run['critical']
                    by_turn[turn_count]['high'] += run['high']
                    by_turn[turn_count]['medium'] += run['medium']
                    by_turn[turn_count]['low'] += run['low']
                else:
                    failed_runs += 1
                    by_turn[turn_count]['failed'] += 1

        # Calculate metrics
        actual_cost = or_data['total_cost']
        cache_savings = or_data['cache_savings']

        results[model] = {
            'actual_cost_total': actual_cost,
            'cache_savings': cache_savings,
            'total_api_calls': or_data['total_calls'],
            'total_runs': total_runs,
            'successful_runs': successful_runs,
            'failed_runs': failed_runs,
            'total_vulnerabilities': total_vulns,
            'total_duration_seconds': total_duration,
            'avg_duration_per_run': total_duration / total_runs if total_runs > 0 else 0,
            'cost_per_run': actual_cost / total_runs if total_runs > 0 else 0,
            'cost_per_vuln': actual_cost / total_vulns if total_vulns > 0 else 0,
            'vulns_per_dollar': total_vulns / actual_cost if actual_cost > 0 else 0,
            'avg_vulns_per_run': total_vulns / successful_runs if successful_runs > 0 else 0,
            'tokens_prompt': or_data['total_tokens_prompt'],
            'tokens_completion': or_data['total_tokens_completion'],
            'by_turn_count': {}
        }

        # Per-turn metrics
        for turn_count, turn_data in by_turn.items():
            turns_int = int(turn_count)
            if turn_data['runs'] == 0:
                continue

            # Estimate cost per turn based on proportion of runs
            turn_cost = actual_cost * (turn_data['runs'] / total_runs)

            results[model]['by_turn_count'][turn_count] = {
                'total_runs': turn_data['runs'],
                'successful_runs': turn_data['successful'],
                'failed_runs': turn_data['failed'],
                'total_vulns': turn_data['vulns'],
                'critical': turn_data['critical'],
                'high': turn_data['high'],
                'medium': turn_data['medium'],
                'low': turn_data['low'],
                'total_duration': turn_data['duration'],
                'avg_duration': turn_data['duration'] / turn_data['runs'],
                'estimated_cost': turn_cost,
                'cost_per_turn': turn_cost / (turns_int * turn_data['runs']),
                'cost_per_run': turn_cost / turn_data['runs'],
                'cost_per_vuln': turn_cost / turn_data['vulns'] if turn_data['vulns'] > 0 else 0,
                'vulns_per_dollar': turn_data['vulns'] / turn_cost if turn_cost > 0 else 0,
                'avg_vulns_per_run': turn_data['vulns'] / turn_data['successful'] if turn_data['successful'] > 0 else 0,
                'vulns_per_turn': turn_data['vulns'] / (turns_int * turn_data['successful']) if turn_data['successful'] > 0 else 0,
            }

    return results

def print_report(results, title="COMPREHENSIVE COST ANALYSIS"):
    """Print comprehensive analysis report"""

    print("=" * 120)
    print(title)
    print("=" * 120)

    # Overall summary
    total_cost = sum(r['actual_cost_total'] for r in results.values())
    total_vulns = sum(r['total_vulnerabilities'] for r in results.values())
    total_cache_savings = sum(r['cache_savings'] for r in results.values())

    print(f"\nTotal Actual Cost: ${total_cost:.2f}")
    print(f"Total Cache Savings: ${total_cache_savings:.2f}")
    print(f"Total Vulnerabilities Found: {total_vulns}")
    print(f"Overall Cost per Vuln: ${total_cost/total_vulns:.4f}" if total_vulns > 0 else "N/A")

    # Cost per vulnerability ranking
    print("\n" + "=" * 120)
    print("1. COST PER VULNERABILITY (Actual OpenRouter Costs)")
    print("=" * 120)
    print(f"{'Model':<35} {'Actual Cost':<12} {'Vulns':<8} {'$/Vuln':<12} {'Vulns/$':<12} {'Success Rate':<12}")
    print("-" * 120)

    ranked = sorted(results.items(), key=lambda x: x[1]['cost_per_vuln'] if x[1]['cost_per_vuln'] > 0 else float('inf'))
    for model, data in ranked:
        if data['total_vulnerabilities'] == 0:
            continue
        success_rate = data['successful_runs'] / data['total_runs'] * 100 if data['total_runs'] > 0 else 0
        print(f"{model:<35} ${data['actual_cost_total']:<11.2f} {data['total_vulnerabilities']:<8} "
              f"${data['cost_per_vuln']:<11.4f} {data['vulns_per_dollar']:<12.1f} {success_rate:<11.1f}%")

    # Total vulnerabilities ranking
    print("\n" + "=" * 120)
    print("2. TOTAL VULNERABILITIES FOUND")
    print("=" * 120)
    print(f"{'Model':<35} {'Total Vulns':<12} {'Avg/Run':<12} {'Critical+High':<15} {'% C+H':<10}")
    print("-" * 120)

    ranked = sorted(results.items(), key=lambda x: x[1]['total_vulnerabilities'], reverse=True)
    for model, data in ranked:
        if data['total_vulnerabilities'] == 0:
            continue
        # Sum critical+high across all turns
        crit_high = sum(t['critical'] + t['high'] for t in data['by_turn_count'].values())
        pct_crit_high = (crit_high / data['total_vulnerabilities'] * 100) if data['total_vulnerabilities'] > 0 else 0
        print(f"{model:<35} {data['total_vulnerabilities']:<12} {data['avg_vulns_per_run']:<12.1f} "
              f"{crit_high:<15} {pct_crit_high:<10.1f}%")

    # Speed ranking
    print("\n" + "=" * 120)
    print("3. SPEED ANALYSIS")
    print("=" * 120)
    print(f"{'Model':<35} {'Avg Duration':<15} {'Total Runs':<12} {'Success Rate':<12}")
    print("-" * 120)

    ranked = sorted(results.items(), key=lambda x: x[1]['avg_duration_per_run'])
    for model, data in ranked:
        success_rate = data['successful_runs'] / data['total_runs'] * 100 if data['total_runs'] > 0 else 0
        print(f"{model:<35} {data['avg_duration_per_run']:<15.1f}s {data['total_runs']:<12} {success_rate:<11.1f}%")

    # Turn count analysis
    print("\n" + "=" * 120)
    print("4. TURN COUNT EFFICIENCY ANALYSIS")
    print("=" * 120)

    for model, data in sorted(results.items(), key=lambda x: x[1]['total_vulnerabilities'], reverse=True):
        if data['total_vulnerabilities'] == 0:
            continue

        print(f"\n{model}:")
        print(f"{'Turns':<8} {'Runs':<8} {'Success':<10} {'Vulns':<8} {'Avg V/Run':<12} {'$/Vuln':<12} {'V/$':<10} {'Dur(s)':<10}")
        print("-" * 100)

        for turn_count in sorted(data['by_turn_count'].keys(), key=lambda x: int(x)):
            td = data['by_turn_count'][turn_count]
            if td['total_vulns'] == 0:
                continue
            print(f"{turn_count:<8} {td['total_runs']:<8} {td['successful_runs']:<10} {td['total_vulns']:<8} "
                  f"{td['avg_vulns_per_run']:<12.1f} ${td['cost_per_vuln']:<11.4f} {td['vulns_per_dollar']:<10.1f} "
                  f"{td['avg_duration']:<10.1f}")

    # Efficiency score
    print("\n" + "=" * 120)
    print("5. EFFICIENCY SCORE (Quality × Value / Cost)")
    print("=" * 120)
    print(f"{'Model':<35} {'Efficiency Score':<20} {'Explanation':<50}")
    print("-" * 120)

    ranked_eff = []
    for model, data in results.items():
        if data['cost_per_vuln'] == 0 or data['total_vulnerabilities'] == 0:
            continue
        # Efficiency = (vulns_per_dollar × avg_vulns_per_run) / (cost_per_vuln × 1000)
        efficiency = (data['vulns_per_dollar'] * data['avg_vulns_per_run']) / (data['cost_per_vuln'] * 1000)
        ranked_eff.append((model, efficiency, data))

    ranked_eff.sort(key=lambda x: x[1], reverse=True)
    for model, efficiency, data in ranked_eff:
        explanation = f"{data['vulns_per_dollar']:.0f} v/$ × {data['avg_vulns_per_run']:.1f} avg"
        print(f"{model:<35} {efficiency:<20.1f} {explanation:<50}")

def main():
    # Parse data
    print("Parsing OpenRouter CSV...")
    benchmark_dir = os.path.join(_project_root(), 'benchmark')
    openrouter_costs = parse_openrouter_csv(os.path.join(benchmark_dir, 'openrouter_activity_2025-10-28.csv'))

    print("Parsing benchmark results...")
    benchmark_data = parse_benchmark_results(os.path.join(benchmark_dir, 'benchmark_metrics.csv'))

    # Calculate metrics for all turns
    print("\nCalculating comprehensive metrics...\n")
    results_all = calculate_comprehensive_metrics(openrouter_costs, benchmark_data)
    print_report(results_all, "COMPREHENSIVE COST ANALYSIS (ALL TURNS)")

    # Calculate metrics for 32/64 turns only (apple-to-apple)
    print("\n\n")
    results_32_64 = calculate_comprehensive_metrics(openrouter_costs, benchmark_data, turn_filters=['32', '64'])
    print_report(results_32_64, "APPLE-TO-APPLE COMPARISON (32 & 64 TURNS ONLY)")

    # Save detailed JSON
    output = {
        'all_turns': results_all,
        'turns_32_64_only': results_32_64,
        'generated_at': datetime.now().isoformat()
    }

    output_file = os.path.join(benchmark_dir, 'actual_costs_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print("\n\n" + "=" * 120)
    print(f"Detailed analysis saved to: {output_file}")
    print("=" * 120)

if __name__ == '__main__':
    main()
