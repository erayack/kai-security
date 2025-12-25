#!/usr/bin/env python3
"""
Generate a comprehensive report for the fixer agent from exploit fix conversations.

This script analyzes exploit fix conversation files to produce statistics about
exploit fixing, including success rates, costs, time spent, and lists of fixed/failed exploits.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
import datetime


def format_time(seconds: float) -> str:
    """Format seconds into human-readable time string."""
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    remaining_seconds = seconds % 60

    if minutes < 60:
        return f"{minutes}m {remaining_seconds:.0f}s"

    hours = int(minutes // 60)
    remaining_minutes = minutes % 60

    return f"{hours}h {remaining_minutes}m {remaining_seconds:.0f}s"


def count_turns_used(messages: List[Dict]) -> int:
    """Count the number of turns used by counting assistant messages."""
    turns = 0
    for msg in messages:
        if msg.get("role") == "assistant":
            content = msg.get("content", "")
            if "<python>" in content or "<think>" in content:
                turns += 1
    return turns


def _extract_location(exploit: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize legacy exploits that still store `locations` arrays."""
    location = exploit.get("location")
    if location:
        return location

    locations = exploit.get("locations")
    if isinstance(locations, list) and locations:
        return locations[0]
    if isinstance(locations, dict):
        return locations
    return None


def load_exploit_info(repo_slug: str) -> Dict[str, Dict]:
    """Load exploit information from all exploits.json files in the repository."""
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    repo_path = project_root / "repos" / repo_slug

    exploits_map = {}  # exploit_id -> exploit_info

    if not repo_path.exists():
        return exploits_map

    # Find all exploits.json files
    for exploits_file in repo_path.rglob("exploits.json"):
        try:
            with open(exploits_file, "r") as f:
                exploits = json.load(f)
                for exploit in exploits:
                    exploit_id = exploit.get("id")
                    if exploit_id:
                        exploits_map[exploit_id] = {
                            "id": exploit_id,
                            "category": exploit.get("category", "Unknown"),
                            "severity": exploit.get("severity", "unknown"),
                            "description": exploit.get("description", ""),
                            "location": _extract_location(exploit),
                        }
        except Exception:
            continue

    return exploits_map


def analyze_fixer_conversations(output_dir: str, repo_slug: str) -> Dict[str, Any]:
    """Analyze all exploit fix conversations and generate report."""

    fixer_dir = Path(output_dir) / repo_slug / "fixer_conversations"

    if not fixer_dir.exists():
        return {"error": f"No exploit fix conversations found at {fixer_dir}"}

    # Load exploit information
    exploits_map = load_exploit_info(repo_slug)

    # Find all conversation files
    conv_files = list(fixer_dir.glob("*.json"))

    if not conv_files:
        return {"error": f"No conversation files found in {fixer_dir}"}

    # Statistics
    total_conversations = len(conv_files)
    fixed_count = 0
    failed_count = 0
    error_count = 0

    total_cost = 0.0
    total_time = 0.0
    total_turns = 0
    total_prompt_tokens = 0
    total_completion_tokens = 0

    # Severity breakdown
    severity_stats = defaultdict(lambda: {"fixed": 0, "failed": 0})

    # Lists of exploits
    fixed_exploits = []
    failed_exploits = []

    # Process each conversation
    for conv_file in conv_files:
        try:
            with open(conv_file, "r") as f:
                convo = json.load(f)

            # Extract basic info
            # Note: fixer_utils saves validation_result with 'fixed' key
            validation_result = convo.get("validation_result", {})
            exploit_id = validation_result.get("exploit_id", "unknown")
            fixed = validation_result.get("fixed", False)
            exception_occurred = validation_result.get("exception_occurred", False)
            suggested_fix = validation_result.get("suggested_fix", None)

            # Get exploit info
            exploit_info = exploits_map.get(
                exploit_id,
                {
                    "id": exploit_id,
                    "category": "Unknown",
                    "severity": "unknown",
                    "description": "No description available",
                    "location": None,
                },
            )

            severity = exploit_info["severity"]

            # Aggregate costs and time
            total_cost += convo.get("estimated_cost", 0.0)
            total_time += convo.get("time_spent", 0.0)
            total_turns += count_turns_used(convo.get("messages", []))

            tokens = convo.get("total_tokens", {})
            total_prompt_tokens += tokens.get("prompt_tokens", 0)
            total_completion_tokens += tokens.get("completion_tokens", 0)

            # Categorize by outcome
            if exception_occurred:
                error_count += 1
                severity_stats[severity]["failed"] += 1
                failed_exploits.append(
                    {
                        **exploit_info,
                        "status": "error",
                        "reason": "Agent encountered an exception",
                        "conversation_file": conv_file.name,
                    }
                )
            elif fixed and suggested_fix:
                fixed_count += 1
                severity_stats[severity]["fixed"] += 1
                fixed_exploits.append(
                    {
                        **exploit_info,
                        "conversation_file": conv_file.name,
                        "suggested_fix_snippet": suggested_fix[:100] + "..."
                        if len(suggested_fix) > 100
                        else suggested_fix,
                    }
                )
            else:
                failed_count += 1
                severity_stats[severity]["failed"] += 1
                failed_exploits.append(
                    {
                        **exploit_info,
                        "status": "failed",
                        "reason": "No fix suggested",
                        "conversation_file": conv_file.name,
                    }
                )

        except Exception as e:
            print(f"Warning: Failed to process {conv_file.name}: {e}")
            continue

    # Calculate rates
    total_exploits = fixed_count + failed_count + error_count
    fix_rate = (fixed_count / total_exploits * 100) if total_exploits > 0 else 0.0

    # Build report
    report = {
        "metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "repo_slug": repo_slug,
            "validation_directory": str(fixer_dir),
        },
        "summary": {
            "total_conversations": total_conversations,
            "total_exploits": total_exploits,
            "fixed_exploits": fixed_count,
            "failed_exploits": failed_count,
            "error_exploits": error_count,
            "fix_rate": round(fix_rate, 1),
            "total_cost": round(total_cost, 4),
            "total_time_seconds": round(total_time, 2),
            "total_time": format_time(total_time),
            "total_turns": total_turns,
            "total_prompt_tokens": total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "total_tokens": total_prompt_tokens + total_completion_tokens,
        },
        "averages": {
            "avg_cost_per_exploit": round(total_cost / total_exploits, 4)
            if total_exploits > 0
            else 0,
            "avg_time_per_exploit_seconds": round(total_time / total_exploits, 2)
            if total_exploits > 0
            else 0,
            "avg_time_per_exploit": format_time(total_time / total_exploits)
            if total_exploits > 0
            else "0s",
            "avg_turns_per_exploit": round(total_turns / total_exploits, 2)
            if total_exploits > 0
            else 0,
            "avg_tokens_per_exploit": round(
                (total_prompt_tokens + total_completion_tokens) / total_exploits, 0
            )
            if total_exploits > 0
            else 0,
        },
        "severity_breakdown": {
            severity: {
                "fixed": stats["fixed"],
                "failed": stats["failed"],
                "total": stats["fixed"] + stats["failed"],
                "fix_rate": round(
                    stats["fixed"] / (stats["fixed"] + stats["failed"]) * 100, 1
                )
                if (stats["fixed"] + stats["failed"]) > 0
                else 0.0,
            }
            for severity, stats in sorted(severity_stats.items())
        },
        "efficiency_metrics": {
            "cost_per_fixed_exploit": round(total_cost / fixed_count, 4)
            if fixed_count > 0
            else 0,
            "time_per_fixed_exploit_seconds": round(total_time / fixed_count, 2)
            if fixed_count > 0
            else 0,
            "time_per_fixed_exploit": format_time(total_time / fixed_count)
            if fixed_count > 0
            else "0s",
            "fixed_per_minute": round(fixed_count / (total_time / 60), 2)
            if total_time > 0
            else 0,
            "exploits_per_dollar": round(total_exploits / total_cost, 2)
            if total_cost > 0
            else 0,
            "fixed_per_dollar": round(fixed_count / total_cost, 2)
            if total_cost > 0
            else 0,
        },
        "fixed_exploits": fixed_exploits,
        "failed_exploits": failed_exploits,
    }

    return report


def save_report(
    report: Dict, output_dir: str, repo_slug: str, filename: str = "fixer_report.json"
) -> str:
    """Save the report to a JSON file."""
    output_path = Path(output_dir) / repo_slug / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return str(output_path)


def generate_fixer_report(
    repo_slug: str, output_dir: str, hyperparams: Dict[str, Any] = None
) -> Dict:
    """
    Generate a comprehensive report from exploit fix conversations.

    Args:
        repo_slug: The repository slug (e.g., "2025-09-monad-60078b9e")
        output_dir: The output directory containing conversations
        hyperparams: Optional dictionary of hyperparameters (not used in this version)

    Returns:
        Dictionary containing the comprehensive report
    """
    return analyze_fixer_conversations(output_dir, repo_slug)


def main():
    """Main function."""
    # Get project root
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    # Default paths - can be overridden with command line args
    import sys

    if len(sys.argv) > 1:
        repo_slug = sys.argv[1]
    else:
        # Try to find the most recent repo
        output_dir = project_root / "output"
        if output_dir.exists():
            repos = [d for d in output_dir.iterdir() if d.is_dir()]
            if repos:
                repo_slug = max(repos, key=lambda p: p.stat().st_mtime).name
            else:
                print("Error: No repositories found in output directory")
                return
        else:
            print("Error: Output directory not found")
            return

    output_dir = project_root / "output"

    print("=" * 80)
    print("FIXER REPORT")
    print("=" * 80)
    print(f"Project root: {project_root}")
    print(f"Output dir: {output_dir}")
    print(f"Repository: {repo_slug}")
    print()

    # Generate report
    print("Analyzing exploit fix conversations...")
    report = generate_fixer_report(repo_slug, str(output_dir))

    if "error" in report:
        print(f"Error: {report['error']}")
        return

    # Save report
    output_file = save_report(report, str(output_dir), repo_slug)

    # Print summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print("=" * 80)
    print(f"Total conversations: {report['summary']['total_conversations']}")
    print(f"Total exploits: {report['summary']['total_exploits']}")
    print(f"  ✅ Fixed: {report['summary']['fixed_exploits']}")
    print(f"  ❌ Failed: {report['summary']['failed_exploits']}")
    print(f"  ⚠️  Errors: {report['summary']['error_exploits']}")
    print(f"Fix rate: {report['summary']['fix_rate']}%")
    print(f"\nTotal cost: ${report['summary']['total_cost']}")
    print(f"Total time: {report['summary']['total_time']}")
    print(f"Total tokens: {report['summary']['total_tokens']:,}")
    print(f"Total turns: {report['summary']['total_turns']}")

    print(f"\nSeverity Breakdown:")
    for severity, stats in report["severity_breakdown"].items():
        print(
            f"  {severity.upper()}: {stats['fixed']}/{stats['total']} fixed ({stats['fix_rate']}%)"
        )

    print(f"\nEfficiency Metrics:")
    print(
        f"  Cost per fixed: ${report['efficiency_metrics']['cost_per_fixed_exploit']}"
    )
    print(f"  Time per fixed: {report['efficiency_metrics']['time_per_fixed_exploit']}")
    print(f"  Fixed per minute: {report['efficiency_metrics']['fixed_per_minute']}")
    print(f"  Fixed per dollar: {report['efficiency_metrics']['fixed_per_dollar']}")

    print(f"\nOutput saved to: {output_file}")
    print("=" * 80)


if __name__ == "__main__":
    main()
