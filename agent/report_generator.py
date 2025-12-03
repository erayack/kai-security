"""
Report generation utilities for aggregating agent statistics.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict
import datetime


def format_time(seconds: float) -> str:
    """
    Format seconds into human-readable time string.
    
    Args:
        seconds: Time in seconds
        
    Returns:
        Formatted string like "1h 23m 45s" or "45m 12s" or "12.5s"
    """
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
    """
    Count the number of turns used (assistant response + engine result = 1 turn).
    
    A turn is counted when we see an assistant message with <python> code.
    """
    turns = 0
    for msg in messages:
        if msg.get('role') == 'assistant' and '<python>' in msg.get('content', ''):
            turns += 1
    return turns


def analyze_agent_depth_stats(all_convos: List[Dict]) -> Dict[int, Dict]:
    """Analyze statistics grouped by agent depth."""
    depth_stats = defaultdict(lambda: {
        'count': 0,
        'total_cost': 0.0,
        'total_exploits': 0,
        'total_turns': 0,
        'total_time': 0.0,
        'exploit_severities': defaultdict(int)
    })
    
    for convo in all_convos:
        depth = convo.get('depth', 0)
        stats = depth_stats[depth]
        
        stats['count'] += 1
        stats['total_cost'] += convo.get('estimated_cost', 0.0)
        stats['total_turns'] += count_turns_used(convo.get('messages', []))
        stats['total_time'] += convo.get('time_spent', 0.0)
        
        # Count exploits found by this agent (not sub-agents)
        found_exploits = convo.get('found_exploits', [])
        stats['total_exploits'] += len(found_exploits)
        
        for exploit in found_exploits:
            severity = exploit.get('severity', 'unknown')
            stats['exploit_severities'][severity] += 1
    
    # Convert to regular dict and add averages
    result = {}
    for depth, stats in depth_stats.items():
        count = stats['count']
        result[depth] = {
            'agent_count': count,
            'total_cost': round(stats['total_cost'], 4),
            'avg_cost_per_agent': round(stats['total_cost'] / count, 4) if count > 0 else 0,
            'total_exploits_found': stats['total_exploits'],
            'avg_exploits_per_agent': round(stats['total_exploits'] / count, 2) if count > 0 else 0,
            'total_turns_used': stats['total_turns'],
            'avg_turns_per_agent': round(stats['total_turns'] / count, 2) if count > 0 else 0,
            'total_time_spent_seconds': round(stats['total_time'], 2),
            'total_time_spent': format_time(stats['total_time']),
            'avg_time_per_agent_seconds': round(stats['total_time'] / count, 2) if count > 0 else 0,
            'avg_time_per_agent': format_time(stats['total_time'] / count) if count > 0 else "0s",
            'exploit_severities': dict(stats['exploit_severities'])
        }
    
    return result


def _analyze_sub_agent_correlation_DEPRECATED(all_convos: List[Dict]) -> Dict:
    """Analyze correlation between number of sub-agents and exploits found."""
    # Group agents by number of sub-agents they spawned
    sub_agent_groups = defaultdict(lambda: {
        'count': 0,
        'total_exploits': 0,
        'total_combined_exploits': 0,
        'exploit_severities': defaultdict(int),
        'combined_severities': defaultdict(int)
    })
    
    for convo in all_convos:
        # Count how many sub-agents this agent spawned
        sub_agent_exploits = convo.get('sub_agent_exploits', [])
        num_sub_agents = len(set(e.get('id', '') for e in sub_agent_exploits if 'id' in e))
        
        # Alternative: count from messages where delegate_to_sub_agent was called
        # This is more accurate
        messages = convo.get('messages', [])
        delegate_count = sum(1 for msg in messages 
                            if msg.get('role') == 'assistant' 
                            and 'delegate_to_sub_agent' in msg.get('content', ''))
        
        num_sub_agents = max(num_sub_agents, delegate_count)
        
        group = sub_agent_groups[num_sub_agents]
        group['count'] += 1
        
        found_exploits = convo.get('found_exploits', [])
        combined_exploits = convo.get('combined_exploits', found_exploits)
        
        group['total_exploits'] += len(found_exploits)
        group['total_combined_exploits'] += len(combined_exploits)
        
        for exploit in found_exploits:
            severity = exploit.get('severity', 'unknown')
            group['exploit_severities'][severity] += 1
        
        for exploit in combined_exploits:
            severity = exploit.get('severity', 'unknown')
            group['combined_severities'][severity] += 1
    
    # Convert to regular dict and add averages
    result = {}
    for num_sub_agents, group in sorted(sub_agent_groups.items()):
        count = group['count']
        result[num_sub_agents] = {
            'agent_count': count,
            'avg_exploits_own': round(group['total_exploits'] / count, 2) if count > 0 else 0,
            'avg_exploits_combined': round(group['total_combined_exploits'] / count, 2) if count > 0 else 0,
            'total_exploits_own': group['total_exploits'],
            'total_exploits_combined': group['total_combined_exploits'],
            'exploit_severities': dict(group['exploit_severities']),
            'combined_severities': dict(group['combined_severities'])
        }
    
    return result


def generate_comprehensive_report(
    repo_slug: str,
    output_dir: str,
    hyperparams: Dict[str, Any]
) -> Dict:
    """
    Generate a comprehensive report from all conversation files.
    
    Args:
        repo_slug: The repository slug (e.g., "gmx-solana-455eb63f")
        output_dir: The output directory containing conversations
        hyperparams: Dictionary of hyperparameters used
        
    Returns:
        Dictionary containing the comprehensive report
    """
    output_path = Path(output_dir) / repo_slug
    
    # Find all conversation files
    main_convo_files = list(output_path.glob("convo_*.json"))
    subagent_convo_files = list((output_path / "sub_agent_convos").glob("*.json"))
    
    all_convo_files = main_convo_files + subagent_convo_files
    
    if not all_convo_files:
        return {
            "error": "No conversation files found",
            "output_path": str(output_path)
        }
    
    # Load all conversations
    all_convos = []
    for file_path in all_convo_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                convo = json.load(f)
                convo['_file'] = file_path.name
                all_convos.append(convo)
        except Exception as e:
            print(f"Warning: Failed to load {file_path}: {e}")
    
    # Find the main agent (depth 0)
    main_agent = next((c for c in all_convos if c.get('depth') == 0), None)
    
    # Calculate total statistics from ALL loaded conversations
    # This ensures we capture costs/exploits from timed-out sub-agents that saved their convos
    total_cost = sum(c.get('estimated_cost', 0.0) for c in all_convos)
    total_exploits = sum(len(c.get('found_exploits', [])) for c in all_convos)
    total_time = sum(c.get('time_spent', 0.0) for c in all_convos)
    
    # For combined stats, use main agent's fields if they match reality, otherwise calculate from all convos
    # Main agent's combined fields are incomplete if sub-agents timed out
    if main_agent:
        main_agent_combined_cost = main_agent.get('combined_total_cost', 0.0)
        main_agent_combined_exploits_count = len(main_agent.get('combined_exploits', []))
        main_agent_combined_time = main_agent.get('combined_time_spent', 0.0)
        
        # Check if main agent's combined fields are complete (no missing sub-agents)
        # If total_cost is significantly higher than main agent's combined cost, sub-agents timed out
        if total_cost > main_agent_combined_cost * 1.1:  # 10% tolerance for rounding
            # Sub-agents timed out, use actual totals from all loaded conversations
            total_combined_cost = total_cost
            total_combined_exploits = total_exploits
            total_combined_time = total_time
        else:
            # All sub-agents completed successfully, use main agent's combined fields
            total_combined_cost = main_agent_combined_cost
            total_combined_exploits = main_agent_combined_exploits_count
            total_combined_time = main_agent_combined_time
    else:
        total_combined_cost = total_cost
        total_combined_exploits = total_exploits
        total_combined_time = total_time
    
    total_turns = sum(count_turns_used(c.get('messages', [])) for c in all_convos)
    
    # Calculate token statistics
    total_prompt_tokens = sum(c.get('total_tokens', {}).get('prompt_tokens', 0) for c in all_convos)
    total_completion_tokens = sum(c.get('total_tokens', {}).get('completion_tokens', 0) for c in all_convos)
    
    # Aggregate exploit severities from ALL conversations
    severity_stats = defaultdict(int)
    
    for convo in all_convos:
        for exploit in convo.get('found_exploits', []):
            severity = exploit.get('severity', 'unknown')
            severity_stats[severity] += 1
    
    # For combined severity stats, use main agent's if complete, otherwise calculate from all convos
    if main_agent and 'combined_exploit_stats' in main_agent:
        main_agent_severity_stats = main_agent['combined_exploit_stats']
        # Check if main agent's stats match the actual totals (no missing sub-agents)
        main_agent_total = sum(main_agent_severity_stats.values())
        if total_exploits > main_agent_total * 1.1:  # 10% tolerance
            # Sub-agents timed out, use actual severity stats from all conversations
            combined_severity_stats = dict(severity_stats)
        else:
            # All sub-agents completed, use main agent's combined stats
            combined_severity_stats = dict(main_agent_severity_stats)
    else:
        combined_severity_stats = dict(severity_stats)
    
    # Count agents by depth
    agents_by_depth = defaultdict(int)
    for convo in all_convos:
        depth = convo.get('depth', 0)
        agents_by_depth[depth] += 1
    
    # Build the report
    report = {
        "metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "repo_slug": repo_slug,
            "total_conversation_files": len(all_convo_files),
            "main_agent_files": len(main_convo_files),
            "subagent_files": len(subagent_convo_files)
        },
        
        "hyperparameters": hyperparams,
        
        "summary": {
            "total_agents": len(all_convos),
            "agents_by_depth": dict(sorted(agents_by_depth.items())),
            "total_cost_all_agents": round(total_cost, 4),
            "total_combined_cost": round(total_combined_cost, 4),
            "total_exploits_found": total_exploits,
            "total_combined_exploits": total_combined_exploits,
            "total_turns_used": total_turns,
            "total_time_spent_seconds": round(total_time, 2),
            "total_time_spent": format_time(total_time),
            "total_combined_time_seconds": round(total_combined_time, 2),
            "total_combined_time": format_time(total_combined_time),
            "total_prompt_tokens": total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "total_tokens": total_prompt_tokens + total_completion_tokens
        },
        
        "averages": {
            "avg_cost_per_agent": round(total_cost / len(all_convos), 4) if all_convos else 0,
            "avg_exploits_per_agent": round(total_exploits / len(all_convos), 2) if all_convos else 0,
            "avg_turns_per_agent": round(total_turns / len(all_convos), 2) if all_convos else 0,
            "avg_time_per_agent_seconds": round(total_time / len(all_convos), 2) if all_convos else 0,
            "avg_time_per_agent": format_time(total_time / len(all_convos)) if all_convos else "0s",
            "avg_tokens_per_agent": round((total_prompt_tokens + total_completion_tokens) / len(all_convos), 0) if all_convos else 0
        },
        
        "exploit_statistics": {
            "by_severity_own": dict(severity_stats),
            "by_severity_combined": combined_severity_stats,
            "severity_percentages": {
                severity: round(count / total_combined_exploits * 100, 1) if total_combined_exploits > 0 else 0
                for severity, count in combined_severity_stats.items()
            }
        },
        
        "depth_analysis": analyze_agent_depth_stats(all_convos),
        
        "efficiency_metrics": {
            "cost_per_exploit": round(total_combined_cost / total_combined_exploits, 4) if total_combined_exploits > 0 else 0,
            "exploits_per_dollar": round(total_combined_exploits / total_combined_cost, 2) if total_combined_cost > 0 else 0,
            "turns_per_exploit": round(total_turns / total_combined_exploits, 2) if total_combined_exploits > 0 else 0,
            "time_per_exploit_seconds": round(total_combined_time / total_combined_exploits, 2) if total_combined_exploits > 0 else 0,
            "time_per_exploit": format_time(total_combined_time / total_combined_exploits) if total_combined_exploits > 0 else "0s",
            "exploits_per_minute": round(total_combined_exploits / (total_combined_time / 60), 2) if total_combined_time > 0 else 0,
            "tokens_per_exploit": round((total_prompt_tokens + total_completion_tokens) / total_combined_exploits, 0) if total_combined_exploits > 0 else 0
        }
    }
    
    # Add main agent specific info if available
    if main_agent:
        report["main_agent"] = {
            "agent_id": main_agent.get('agent_id'),
            "model": main_agent.get('model'),
            "cost": round(main_agent.get('estimated_cost', 0.0), 4),
            "combined_cost": round(main_agent.get('combined_total_cost', 0.0), 4),
            "exploits_found": len(main_agent.get('found_exploits', [])),
            "combined_exploits": len(main_agent.get('combined_exploits', [])),
            "turns_used": count_turns_used(main_agent.get('messages', [])),
            "time_spent_seconds": round(main_agent.get('time_spent', 0.0), 2),
            "time_spent": format_time(main_agent.get('time_spent', 0.0)),
            "combined_time_spent_seconds": round(main_agent.get('combined_time_spent', 0.0), 2),
            "combined_time_spent": format_time(main_agent.get('combined_time_spent', 0.0)),
            "sub_agents_spawned": len(main_agent.get('sub_agent_exploits', []))
        }
    
    return report


def save_report(report: Dict, output_dir: str, repo_slug: str) -> str:
    """Save the report to a JSON file."""
    output_path = Path(output_dir) / repo_slug / "report.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return str(output_path)

