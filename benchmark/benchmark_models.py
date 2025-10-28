import os
import sys
import json
import time
import asyncio
import subprocess
import hashlib
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from tqdm.asyncio import tqdm as async_tqdm

# Add project root to Python path so we can import agent module
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Also set PYTHONPATH environment variable for subprocesses spawned by agent tools
current_pythonpath = os.environ.get("PYTHONPATH", "")
if current_pythonpath:
    os.environ["PYTHONPATH"] = f"{_PROJECT_ROOT}{os.pathsep}{current_pythonpath}"
else:
    os.environ["PYTHONPATH"] = _PROJECT_ROOT

# Models to benchmark
MODELS = [
    "z-ai/glm-4.6",
    "x-ai/grok-code-fast-1",
    "anthropic/claude-sonnet-4.5",
    "google/gemini-2.5-pro",
    "google/gemini-2.5-flash",
    "deepseek/deepseek-chat-v3.1",
    "openai/gpt-5",
    "openai/gpt-4.1",
    "openai/gpt-5-codex",
    "moonshotai/kimi-k2-0905"
]

def _project_root() -> str:
    return str(Path(__file__).resolve().parent.parent)

def _repos_root() -> str:
    root = os.path.join(_project_root(), "repos")
    os.makedirs(root, exist_ok=True)
    return root

def _repo_slug(repo_url: str) -> str:
    """Derive a filesystem-safe slug from repo name + short hash of URL"""
    name = Path(repo_url.rstrip('.git').split("/")[-1]).stem or "repo"
    short_hash = hashlib.sha1(repo_url.encode("utf-8")).hexdigest()[:8]
    safe_name = name.replace(" ", "-")
    return f"{safe_name}-{short_hash}"

def _repo_path(repo_url: str) -> str:
    return os.path.join(_repos_root(), _repo_slug(repo_url))

def clone_repo(repo_url: str) -> str:
    """Clone the repository if it doesn't exist"""
    dest = _repo_path(repo_url)
    if not os.path.exists(dest):
        print(f"Cloning {repo_url} to {dest}...")
        subprocess.run(["git", "clone", repo_url, dest], check=True, capture_output=True)
    else:
        print(f"Repository already cloned at {dest}")
    return dest

def extract_cost_from_conversation(conversation_file: str) -> float:
    """
    Extract cost information from conversation files if available.
    This is a placeholder - you may need to adjust based on actual format.
    """
    # OpenRouter may include cost info in response headers or you need to calculate
    # based on token counts. This is a placeholder implementation.
    return 0.0

def count_vulnerabilities_by_level(exploits_file: str) -> Dict[str, int]:
    """Count vulnerabilities by severity level"""
    if not os.path.exists(exploits_file):
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}

    try:
        with open(exploits_file, 'r') as f:
            exploits = json.load(f)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for exploit in exploits:
            severity = exploit.get("severity", "info").lower()
            if severity in counts:
                counts[severity] += 1

        counts["total"] = len(exploits)
        return counts
    except Exception as e:
        print(f"Error counting vulnerabilities: {e}")
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}

async def run_finder_for_model(repo_url: str, model: str, num_turns: int) -> Dict[str, Any]:
    """Run the finder agent for a specific model and collect statistics (async)"""
    start_time = time.time()

    # Create a unique repo path for this model to avoid conflicts
    base_repo_path = _repo_path(repo_url)
    model_safe_name = model.replace("/", "_")
    repo_path = f"{base_repo_path}_{model_safe_name}"

    # Import here to avoid circular imports
    from agent.agents import FinderAgent
    import shutil

    try:
        # Clone the repo for this specific model if it doesn't exist
        if not os.path.exists(repo_path):
            if not os.path.exists(base_repo_path):
                # Run clone_repo synchronously since it's a subprocess
                await asyncio.to_thread(clone_repo, repo_url)
            # Copy repo in thread to avoid blocking
            await asyncio.to_thread(shutil.copytree, base_repo_path, repo_path)

        # Initialize and run the finder agent in a thread (LLM calls are blocking)
        def run_agent():
            agent = FinderAgent(
                repo_path=repo_path,
                model=model,
                max_tool_turns=num_turns,
                use_openai=False
            )
            BASE_INSTRUCTION = "You must start your search for exploits now"
            response = agent.chat(BASE_INSTRUCTION)
            
            # Save conversation
            save_folder = os.path.join(_project_root(), "benchmark_output", _repo_slug(repo_url), model_safe_name)
            os.makedirs(save_folder, exist_ok=True)
            agent.save_conversation(save_folder=save_folder, prefix="finder")
            
            # Get exploits file path from the model-specific repo
            exploits_file = os.path.join(repo_path, "exploits.json")
            vuln_counts = count_vulnerabilities_by_level(exploits_file)
            cost = calculate_approximate_cost(model, agent.messages)
            
            return vuln_counts, cost, len(agent.messages)
        
        # Run agent in thread pool
        vuln_counts, cost, message_count = await asyncio.to_thread(run_agent)

        end_time = time.time()
        duration = end_time - start_time

        result = {
            "model": model,
            "duration_seconds": duration,
            "duration_formatted": f"{duration:.2f}s",
            "cost_usd": cost,
            "vulnerabilities": vuln_counts,
            "message_count": message_count,
            "status": "success",
            "timestamp": datetime.now().isoformat()
        }

        return result

    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        
        # Print full traceback for debugging
        print(f"\n{'='*60}")
        print(f"ERROR in {model}:")
        print(f"{'='*60}")
        traceback.print_exc()
        print(f"{'='*60}\n")

        result = {
            "model": model,
            "duration_seconds": duration,
            "duration_formatted": f"{duration:.2f}s",
            "cost_usd": 0.0,
            "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
            "message_count": 0,
            "status": "failed",
            "error": str(e),
            "traceback": traceback.format_exc(),
            "timestamp": datetime.now().isoformat()
        }

        return result

def calculate_approximate_cost(model: str, messages: List[Any]) -> float:
    """
    Calculate approximate cost based on model and token counts.
    Uses actual OpenRouter pricing as of October 2025.
    """
    # Rough token count estimation
    total_chars = sum(len(str(msg.content)) for msg in messages)
    estimated_tokens = total_chars / 4  # Rough estimate: 1 token ≈ 4 chars

    # Actual OpenRouter pricing (per 1M tokens) - October 2025
    pricing = {
        "anthropic/claude-sonnet-4.5": {"input": 3.0, "output": 15.0},
        "google/gemini-2.5-pro": {"input": 1.25, "output": 10.0},
        "google/gemini-2.5-flash": {"input": 0.30, "output": 2.50},
        "deepseek/deepseek-chat-v3.1": {"input": 0.27, "output": 1.0},
        "openai/gpt-5": {"input": 1.25, "output": 10.0},
        "openai/gpt-4.1": {"input": 2.0, "output": 8.0},
        "openai/gpt-5-codex": {"input": 1.25, "output": 10.0},
        "x-ai/grok-code-fast-1": {"input": 0.20, "output": 1.50},
        "z-ai/glm-4.6": {"input": 0.50, "output": 1.75},
        "moonshotai/kimi-k2-0905": {"input": 0.39, "output": 1.90},
    }

    if model not in pricing:
        # Default pricing for unknown models
        return (estimated_tokens / 1_000_000) * 2.0

    # Assume 30% input, 70% output tokens
    input_tokens = estimated_tokens * 0.3
    output_tokens = estimated_tokens * 0.7

    cost = (input_tokens / 1_000_000) * pricing[model]["input"] + \
           (output_tokens / 1_000_000) * pricing[model]["output"]

    return cost

async def run_benchmark_parallel(repo_url: str, num_turns: int = 64, max_workers: int = 5):
    """
    Run benchmarks for all models in parallel using asyncio.

    Args:
        repo_url: The repository URL to scan
        num_turns: Maximum number of tool turns per agent
        max_workers: Maximum number of concurrent tasks
    """
    print(f"\n{'='*60}")
    print("Starting Multi-Model Benchmark (Async)")
    print(f"{'='*60}")
    print(f"Repository: {repo_url}")
    print(f"Models to test: {len(MODELS)}")
    print(f"Max concurrent tasks: {max_workers}")
    print(f"{'='*60}\n")

    # Clone the repository first
    repo_path = await asyncio.to_thread(clone_repo, repo_url)

    # Create output directory
    benchmark_dir = os.path.join(_project_root(), "benchmark_output", _repo_slug(repo_url))
    os.makedirs(benchmark_dir, exist_ok=True)

    # Create semaphore to limit concurrent tasks
    semaphore = asyncio.Semaphore(max_workers)
    
    async def run_with_semaphore(model):
        async with semaphore:
            return await run_finder_for_model(repo_url, model, num_turns)
    
    # Run all models concurrently with progress bar
    tasks = [run_with_semaphore(model) for model in MODELS]
    results = []
    
    # Use tqdm for async progress tracking
    for coro in async_tqdm(asyncio.as_completed(tasks), total=len(MODELS), desc="Benchmarking models"):
        try:
            result = await coro
            results.append(result)
            # Print summary after each completion
            status = "✓" if result["status"] == "success" else "✗"
            vulns = result.get("vulnerabilities", {}).get("total", 0)
            duration = result.get("duration_seconds", 0)
            print(f"{status} {result['model']}: {vulns} vulns in {duration:.1f}s")
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            traceback.print_exc()

    # Save results
    results_file = os.path.join(benchmark_dir, "benchmark_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Generate comparison report
    generate_comparison_report(results, benchmark_dir)

    print(f"\n{'='*60}")
    print("Benchmark Complete!")
    print(f"{'='*60}")
    print(f"Results saved to: {results_file}")
    print(f"Comparison report: {os.path.join(benchmark_dir, 'comparison_report.md')}")

def generate_comparison_report(results: List[Dict[str, Any]], output_dir: str):
    """Generate a markdown comparison report"""
    report_file = os.path.join(output_dir, "comparison_report.md")

    # Sort results by total vulnerabilities found (descending)
    sorted_results = sorted(results, key=lambda x: x.get("vulnerabilities", {}).get("total", 0), reverse=True)

    with open(report_file, 'w') as f:
        f.write("# Model Benchmark Comparison Report\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Summary statistics
        f.write("## Summary Statistics\n\n")
        successful = [r for r in results if r.get("status") == "success"]
        failed = [r for r in results if r.get("status") == "failed"]

        f.write(f"- Total models tested: {len(results)}\n")
        f.write(f"- Successful runs: {len(successful)}\n")
        f.write(f"- Failed runs: {len(failed)}\n\n")

        if successful:
            total_cost = sum(r.get("cost_usd", 0) for r in successful)
            avg_duration = sum(r.get("duration_seconds", 0) for r in successful) / len(successful)
            f.write(f"- Total cost: ${total_cost:.4f}\n")
            f.write(f"- Average duration: {avg_duration:.2f}s\n\n")

        # Detailed results table
        f.write("## Detailed Results\n\n")
        f.write("| Model | Status | Duration | Cost | Critical | High | Medium | Low | Info | Total |\n")
        f.write("|-------|--------|----------|------|----------|------|--------|-----|------|-------|\n")

        for result in sorted_results:
            model = result.get("model", "Unknown")
            status = "✓" if result.get("status") == "success" else "✗"
            duration = result.get("duration_formatted", "N/A")
            cost = f"${result.get('cost_usd', 0):.4f}"
            vulns = result.get("vulnerabilities", {})

            f.write(f"| {model} | {status} | {duration} | {cost} | "
                   f"{vulns.get('critical', 0)} | {vulns.get('high', 0)} | "
                   f"{vulns.get('medium', 0)} | {vulns.get('low', 0)} | "
                   f"{vulns.get('info', 0)} | {vulns.get('total', 0)} |\n")

        # Cost analysis
        f.write("\n## Cost Analysis\n\n")
        if successful:
            sorted_by_cost = sorted(successful, key=lambda x: x.get("cost_usd", 0))
            f.write("### Most Cost-Effective Models\n\n")
            for result in sorted_by_cost[:3]:
                vulns_per_dollar = result.get("vulnerabilities", {}).get("total", 0) / max(result.get("cost_usd", 0.0001), 0.0001)
                f.write(f"- **{result['model']}**: ${result.get('cost_usd', 0):.4f} "
                       f"({result.get('vulnerabilities', {}).get('total', 0)} vulns, "
                       f"{vulns_per_dollar:.1f} vulns/$)\n")

        # Performance analysis
        f.write("\n## Performance Analysis\n\n")
        if successful:
            sorted_by_speed = sorted(successful, key=lambda x: x.get("duration_seconds", float('inf')))
            f.write("### Fastest Models\n\n")
            for result in sorted_by_speed[:3]:
                f.write(f"- **{result['model']}**: {result.get('duration_formatted', 'N/A')} "
                       f"({result.get('vulnerabilities', {}).get('total', 0)} vulnerabilities)\n")

        # Quality analysis
        f.write("\n## Quality Analysis\n\n")
        if successful:
            f.write("### Most Vulnerabilities Found\n\n")
            for result in sorted_results[:3]:
                if result.get("status") == "success":
                    vulns = result.get("vulnerabilities", {})
                    f.write(f"- **{result['model']}**: {vulns.get('total', 0)} total "
                           f"(Critical: {vulns.get('critical', 0)}, High: {vulns.get('high', 0)})\n")

        # Failed models
        if failed:
            f.write("\n## Failed Runs\n\n")
            for result in failed:
                f.write(f"- **{result['model']}**: {result.get('error', 'Unknown error')}\n")

    print(f"\nComparison report generated: {report_file}")

async def run_multi_repo_benchmark(repo_urls: List[str], num_turns: int = 64, max_workers: int = 5):
    """
    Run benchmarks across multiple repositories and generate aggregated reports (async).

    Args:
        repo_urls: List of repository URLs to scan
        num_turns: Maximum tool turns per agent
        max_workers: Maximum parallel workers
    """
    print(f"\n{'='*60}")
    print("Multi-Repository Benchmark (Async)")
    print(f"{'='*60}")
    print(f"Repositories to scan: {len(repo_urls)}")
    print(f"Models to test: {len(MODELS)}")
    print(f"{'='*60}\n")

    all_results = {}

    for repo_url in repo_urls:
        print(f"\n\n{'#'*60}")
        print(f"# Processing: {repo_url}")
        print(f"{'#'*60}\n")

        await run_benchmark_parallel(repo_url, num_turns, max_workers)

        # Load results for this repo
        benchmark_dir = os.path.join(_project_root(), "benchmark_output", _repo_slug(repo_url))
        results_file = os.path.join(benchmark_dir, "benchmark_results.json")

        with open(results_file, 'r') as f:
            all_results[repo_url] = json.load(f)

    # Load ALL existing results (including previous runs) and generate aggregated report
    all_existing_results = load_all_benchmark_results()
    generate_multi_repo_report(all_existing_results)

    print(f"\n{'='*60}")
    print("Multi-Repository Benchmark Complete!")
    print(f"{'='*60}")
    print(f"Total repositories in aggregated report: {len(all_existing_results)}")
    print(f"Aggregated report: {os.path.join(_project_root(), 'benchmark_output', 'multi_repo_comparison.md')}")

def load_all_benchmark_results() -> Dict[str, List[Dict[str, Any]]]:
    """Load all existing benchmark results from all repository directories"""
    benchmark_base = os.path.join(_project_root(), "benchmark_output")
    all_results = {}

    if not os.path.exists(benchmark_base):
        return all_results

    # Iterate through all repo directories
    for repo_dir in os.listdir(benchmark_base):
        repo_path = os.path.join(benchmark_base, repo_dir)
        results_file = os.path.join(repo_path, "benchmark_results.json")

        if os.path.isdir(repo_path) and os.path.exists(results_file):
            try:
                with open(results_file, 'r') as f:
                    results = json.load(f)
                    # Use the directory name as the key
                    all_results[repo_dir] = results
            except Exception as e:
                print(f"Warning: Could not load results from {repo_dir}: {e}")

    return all_results

def generate_multi_repo_report(all_results: Dict[str, List[Dict[str, Any]]]):
    """Generate an aggregated comparison report across multiple repositories"""
    output_dir = os.path.join(_project_root(), "benchmark_output")
    os.makedirs(output_dir, exist_ok=True)
    report_file = os.path.join(output_dir, "multi_repo_comparison.md")

    with open(report_file, 'w') as f:
        f.write("# Multi-Repository Model Benchmark Report\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Overall summary
        f.write("## Overall Summary\n\n")
        f.write(f"- Total repositories tested: {len(all_results)}\n")
        f.write(f"- Models tested: {len(MODELS)}\n\n")

        # Per-model aggregation
        model_stats = {}
        for model in MODELS:
            model_stats[model] = {
                "total_vulns": 0,
                "total_cost": 0.0,
                "total_duration": 0.0,
                "success_count": 0,
                "fail_count": 0,
                "repos": []
            }

        for repo_url, results in all_results.items():
            for result in results:
                model = result["model"]
                if model in model_stats:
                    stats = model_stats[model]
                    stats["repos"].append(repo_url)

                    if result.get("status") == "success":
                        stats["success_count"] += 1
                        stats["total_vulns"] += result.get("vulnerabilities", {}).get("total", 0)
                        stats["total_cost"] += result.get("cost_usd", 0)
                        stats["total_duration"] += result.get("duration_seconds", 0)
                    else:
                        stats["fail_count"] += 1

        # Model comparison table
        f.write("## Model Performance Across All Repositories\n\n")
        f.write("| Model | Success | Failed | Total Vulns | Avg Vulns/Repo | Total Cost | Avg Duration |\n")
        f.write("|-------|---------|--------|-------------|----------------|------------|-------------|\n")

        sorted_models = sorted(model_stats.items(), key=lambda x: x[1]["total_vulns"], reverse=True)

        for model, stats in sorted_models:
            success = stats["success_count"]
            failed = stats["fail_count"]
            total_vulns = stats["total_vulns"]
            avg_vulns = total_vulns / success if success > 0 else 0
            total_cost = stats["total_cost"]
            avg_duration = stats["total_duration"] / success if success > 0 else 0

            f.write(f"| {model} | {success} | {failed} | {total_vulns} | {avg_vulns:.1f} | "
                   f"${total_cost:.4f} | {avg_duration:.1f}s |\n")

        # Per-repository breakdown
        f.write("\n## Per-Repository Results\n\n")

        for repo_url, results in all_results.items():
            repo_name = _repo_slug(repo_url)
            f.write(f"\n### {repo_name}\n\n")
            f.write(f"Repository: `{repo_url}`\n\n")

            # Sort by vulnerabilities found
            sorted_results = sorted(results, key=lambda x: x.get("vulnerabilities", {}).get("total", 0), reverse=True)

            f.write("| Model | Status | Vulns | Cost | Duration |\n")
            f.write("|-------|--------|-------|------|----------|\n")

            for result in sorted_results:
                model = result.get("model", "Unknown")
                status = "✓" if result.get("status") == "success" else "✗"
                vulns = result.get("vulnerabilities", {}).get("total", 0)
                cost = f"${result.get('cost_usd', 0):.4f}"
                duration = result.get("duration_formatted", "N/A")

                f.write(f"| {model} | {status} | {vulns} | {cost} | {duration} |\n")

        # Best models analysis
        f.write("\n## Best Models by Metric\n\n")

        f.write("### Most Vulnerabilities Found (Total)\n")
        top_by_vulns = sorted(model_stats.items(), key=lambda x: x[1]["total_vulns"], reverse=True)[:3]
        for model, stats in top_by_vulns:
            if stats['success_count'] > 0:
                f.write(f"- **{model}**: {stats['total_vulns']} total ({stats['total_vulns']/stats['success_count']:.1f} avg per repo)\n")
            else:
                f.write(f"- **{model}**: {stats['total_vulns']} total (no successful runs)\n")

        f.write("\n### Most Cost-Effective\n")
        cost_effective = [(m, s["total_vulns"]/max(s["total_cost"], 0.0001))
                         for m, s in model_stats.items() if s["success_count"] > 0]
        cost_effective.sort(key=lambda x: x[1], reverse=True)
        for model, vulns_per_dollar in cost_effective[:3]:
            stats = model_stats[model]
            f.write(f"- **{model}**: {vulns_per_dollar:.1f} vulns/$ "
                   f"(${stats['total_cost']:.4f} total, {stats['total_vulns']} vulns)\n")

        f.write("\n### Fastest Average Time\n")
        fastest = [(m, s["total_duration"]/s["success_count"])
                  for m, s in model_stats.items() if s["success_count"] > 0]
        fastest.sort(key=lambda x: x[1])
        for model, avg_time in fastest[:3]:
            stats = model_stats[model]
            f.write(f"- **{model}**: {avg_time:.1f}s avg ({stats['total_vulns']} total vulns)\n")

        # Failed models
        failed_models = [(m, s) for m, s in model_stats.items() if s["fail_count"] > 0]
        if failed_models:
            f.write("\n### Models with Failures\n")
            for model, stats in failed_models:
                f.write(f"- **{model}**: {stats['fail_count']}/{stats['fail_count']+stats['success_count']} runs failed\n")

def run_turn_count_experiments(repo_urls: List[str], turn_counts: List[int], max_workers: int = 5):
    """
    Run benchmarks with different turn counts to analyze when models stop finding vulnerabilities.

    Args:
        repo_urls: List of repository URLs to scan
        turn_counts: List of turn counts to test (e.g., [32, 64, 128, 256])
        max_workers: Maximum parallel workers
    """
    print(f"\n{'='*60}")
    print("Turn Count Experiment")
    print(f"{'='*60}")
    print(f"Repositories: {len(repo_urls)}")
    print(f"Turn counts to test: {turn_counts}")
    print(f"Models: {len(MODELS)}")
    print(f"{'='*60}\n")

    for turn_count in turn_counts:
        print(f"\n{'#'*60}")
        print(f"# Testing with {turn_count} turns")
        print(f"{'#'*60}\n")

        for repo_url in repo_urls:
            print(f"\n## Repository: {repo_url}")
            # Modify the benchmark dir to include turn count
            original_slug = _repo_slug(repo_url)

            # Temporarily modify the benchmark to save with turn count suffix
            run_benchmark_with_turn_suffix(repo_url, turn_count, max_workers)

    # Generate comprehensive report
    all_results = load_all_benchmark_results()
    generate_turn_count_analysis_report(all_results, turn_counts)

    print(f"\n{'='*60}")
    print("Turn Count Experiment Complete!")
    print(f"{'='*60}")
    print(f"Analysis report: {os.path.join(_project_root(), 'benchmark_output', 'turn_count_analysis.md')}")

def run_benchmark_with_turn_suffix(repo_url: str, num_turns: int, max_workers: int):
    """Run benchmark and save results with turn count in directory name"""
    # This is a modified version that includes turn count in the output path
    # Clone the repository first
    repo_path = clone_repo(repo_url)

    # Create output directory with turn count suffix
    base_slug = _repo_slug(repo_url)
    benchmark_dir = os.path.join(_project_root(), "benchmark_output", f"{base_slug}_turns{num_turns}")
    os.makedirs(benchmark_dir, exist_ok=True)

    # Run benchmarks in parallel
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_model = {
            executor.submit(run_finder_for_model, repo_url, model, num_turns): model
            for model in MODELS
        }

        for future in tqdm(as_completed(future_to_model), total=len(MODELS), desc=f"Turn={num_turns}"):
            model = future_to_model[future]
            try:
                result = future.result()
                result["num_turns"] = num_turns  # Add turn count to result
                results.append(result)
            except Exception as e:
                print(f"Error with model {model}: {e}")
                results.append({
                    "model": model,
                    "num_turns": num_turns,
                    "status": "failed",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })

    # Save results
    results_file = os.path.join(benchmark_dir, "benchmark_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Generate comparison report
    generate_comparison_report(results, benchmark_dir)

def generate_turn_count_analysis_report(all_results: Dict[str, List[Dict[str, Any]]], turn_counts: List[int]):
    """Generate analysis report comparing different turn counts"""
    output_dir = os.path.join(_project_root(), "benchmark_output")
    report_file = os.path.join(output_dir, "turn_count_analysis.md")

    with open(report_file, 'w') as f:
        f.write("# Turn Count Analysis Report\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Turn counts tested: {', '.join(map(str, sorted(turn_counts)))}\n\n")

        # Group results by repo and turn count
        repo_turn_results = {}
        for repo_key, results in all_results.items():
            # Extract base repo name and turn count from directory name
            if "_turns" in repo_key:
                parts = repo_key.rsplit("_turns", 1)
                base_repo = parts[0]
                try:
                    turns = int(parts[1])
                except:
                    continue

                if base_repo not in repo_turn_results:
                    repo_turn_results[base_repo] = {}
                repo_turn_results[base_repo][turns] = results

        # Analyze each repository
        for repo_name, turn_data in repo_turn_results.items():
            f.write(f"\n## Repository: {repo_name}\n\n")

            # Per-model analysis
            model_analysis = {}
            for turns, results in turn_data.items():
                for result in results:
                    model = result.get("model")
                    if model not in model_analysis:
                        model_analysis[model] = {}

                    model_analysis[model][turns] = {
                        "vulns": result.get("vulnerabilities", {}).get("total", 0),
                        "duration": result.get("duration_seconds", 0),
                        "cost": result.get("cost_usd", 0),
                        "status": result.get("status", "unknown")
                    }

            # Create comparison table
            f.write("| Model | " + " | ".join([f"{t} turns" for t in sorted(turn_counts)]) + " |\n")
            f.write("|-------|" + "|".join(["--------"] * len(turn_counts)) + "|\n")

            for model, turn_results in sorted(model_analysis.items()):
                row = [f"{model}"]
                for turns in sorted(turn_counts):
                    if turns in turn_results:
                        data = turn_results[turns]
                        if data["status"] == "success":
                            row.append(f"{data['vulns']} vulns<br>${data['cost']:.3f}<br>{data['duration']:.0f}s")
                        else:
                            row.append("✗ Failed")
                    else:
                        row.append("N/A")
                f.write("| " + " | ".join(row) + " |\n")

            # Analysis of diminishing returns
            f.write("\n### Diminishing Returns Analysis\n\n")
            for model, turn_results in sorted(model_analysis.items()):
                sorted_turns = sorted([t for t in turn_counts if t in turn_results])
                if len(sorted_turns) < 2:
                    continue

                f.write(f"**{model}:**\n")
                prev_vulns = 0
                for turns in sorted_turns:
                    data = turn_results[turns]
                    if data["status"] == "success":
                        vulns = data["vulns"]
                        new_vulns = vulns - prev_vulns
                        efficiency = new_vulns / turns if turns > 0 else 0
                        f.write(f"- {turns} turns: {vulns} total ({new_vulns:+d} new, {efficiency:.3f} vulns/turn)\n")
                        prev_vulns = vulns
                f.write("\n")

        # Summary recommendations
        f.write("\n## Recommendations\n\n")
        f.write("Based on the analysis above, optimal turn counts for each model:\n\n")
        # Add logic to recommend optimal turn counts based on cost/benefit analysis

async def async_main():
    """Async main entry point for benchmarking"""
    import argparse

    parser = argparse.ArgumentParser(description="Benchmark vulnerability scanner with multiple models (Async)")
    parser.add_argument("repo_urls", nargs='+', help="Repository URL(s) to scan (space-separated for multiple repos)")
    parser.add_argument("--num-turns", type=int, default=64, help="Maximum tool turns per agent (default: 64)")
    parser.add_argument("--max-workers", type=int, default=10, help="Maximum concurrent tasks (default: 10)")
    parser.add_argument("--turn-experiments", nargs='+', type=int,
                       help="Run experiments with different turn counts (e.g., --turn-experiments 32 64 128 256)")

    args = parser.parse_args()

    if args.turn_experiments:
        # Turn count experiment mode - not yet converted to async
        print("Turn count experiments not yet supported in async mode")
        return
    elif len(args.repo_urls) == 1:
        # Single repo mode
        await run_benchmark_parallel(args.repo_urls[0], args.num_turns, args.max_workers)
    else:
        # Multi-repo mode
        await run_multi_repo_benchmark(args.repo_urls, args.num_turns, args.max_workers)

def main():
    """Entry point - runs async main"""
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
