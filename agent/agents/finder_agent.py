from agent.agent import BaseAgent
from agent.utils import AgentType
from agent.schemas import (
    AgentResponse, 
    SubAgentReport, 
    ExploitSummary, 
    CodeReference,
    Exploit,
    Role
)
from agent.settings import MAX_DEPTH
import os
import json
from typing import List


class FinderAgent(BaseAgent):
    """Agent for finding exploits in a codebase."""
    
    def __init__(
        self,
        max_tool_turns: int = None,
        repo_path: str = None,
        use_vllm: bool = False,
        model: str = None,
        use_openai: bool = False,
        scope_paths: list = None,
        parent_agent_id: str = None,
        depth: int = 0,
        max_depth: int = MAX_DEPTH,
    ):
        from agent.settings import MAX_TOOL_TURNS
        if max_tool_turns is None:
            max_tool_turns = MAX_TOOL_TURNS
            
        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            use_openai=use_openai,
            agent_type=AgentType.FINDER,
            scope_paths=scope_paths,
            parent_agent_id=parent_agent_id,
            depth=depth,
            max_depth=max_depth,
        )
    
    def check_termination(self, response: str, python_code: str) -> bool:
        """
        Finder agent never terminates early - always runs until max_tool_turns.
        
        This allows both main agents and sub-agents to use their full turn budget
        to find as many exploits as possible.
        
        Args:
            response: The full response from the model.
            python_code: The extracted python code from the response.
            
        Returns:
            Always returns False to continue until max turns exhausted.
        """
        # Finder agents always use their full turn budget
        return False
    
    def get_tools_module(self) -> str:
        """
        Get the tools module for finder agent.
        
        Returns:
            The tools module name.
        """
        return "agent.tools.finder_tools"
    
    def extract_final_result(self, thoughts: str, python_code: str, response: str) -> AgentResponse:
        """
        Extract the final result for finder agent.
        
        Args:
            thoughts: The extracted thoughts.
            python_code: The extracted python code.
            response: The full response.
            
        Returns:
            An AgentResponse with thoughts and python_block.
        """
        return AgentResponse(thoughts=thoughts, python_block=python_code, test_script="")
    
    def _extract_exploits_from_messages(self) -> List[Exploit]:
        """Extract exploits that were found during this agent's execution."""
        exploits = []
        try:
            # Read the exploits.json file from agent's working directory
            if os.path.exists(self.exploits_path):
                with open(self.exploits_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for exploit_data in data:
                            try:
                                exploit = Exploit(**exploit_data)
                                exploits.append(exploit)
                            except Exception:
                                pass  # Skip invalid exploits
        except Exception:
            pass  # If file doesn't exist or can't be read, return empty list
        
        return exploits
    
    def _extract_files_from_messages(self) -> List[str]:
        """Extract list of files that were read during exploration."""
        files_explored = []
        
        for msg in self.messages:
            if msg.role == Role.ASSISTANT and "<python>" in msg.content:
                # Extract read_file calls
                if "read_file(" in msg.content:
                    # Simple extraction - look for file paths in read_file calls
                    import re
                    matches = re.findall(r'read_file\(["\']([^"\']+)["\']', msg.content)
                    files_explored.extend(matches)
        
        # Remove duplicates and return
        return list(set(files_explored))
    
    def _extract_task_from_messages(self) -> str:
        """Extract the task description from the first user message."""
        for msg in self.messages:
            if msg.role == Role.USER:
                # Return first 200 chars of first user message as task
                return msg.content[:200]
        return "Explore and find exploits"
    
    def _generate_summary_text(self, exploits: List[Exploit], files: List[str]) -> str:
        """Generate 2-5 sentence summary of exploration."""
        scope_desc = self.scope_paths[0] if self.scope_paths else self.repo_path
        
        if not exploits:
            return (
                f"Explored {len(files)} files in {scope_desc}. "
                f"No exploits found. The code in this area appears secure "
                f"or requires deeper manual analysis."
            )
        
        severity_counts = {}
        for e in exploits:
            severity_counts[e.severity.value] = severity_counts.get(e.severity.value, 0) + 1
        
        summary = f"Explored {len(files)} files and found {len(exploits)} exploits. "
        summary += "Severity breakdown: "
        summary += ", ".join(f"{count} {sev}" for sev, count in severity_counts.items())
        summary += ". "
        
        # Add pattern insights
        categories = list(set(e.category for e in exploits))
        if len(categories) <= 3:
            summary += f"Main vulnerability patterns: {', '.join(categories)}."
        else:
            summary += f"Multiple vulnerability patterns detected across {len(categories)} categories."
        
        return summary[:500]  # Enforce max length
    
    def generate_report(self) -> SubAgentReport:
        """Generate structured SubAgentReport from conversation history."""
        
        # Extract exploits added during this agent's execution
        exploits_found = self._extract_exploits_from_messages()
        
        # Extract files that were read
        files_explored = self._extract_files_from_messages()
        
        # Convert exploits to compact summaries
        exploit_summaries = []
        code_references = []
        
        priority_map = {"critical": 10, "high": 8, "medium": 5, "low": 3}
        
        for exploit in exploits_found:
            if exploit.locations and len(exploit.locations) > 0:
                loc = exploit.locations[0]  # Primary location
                try:
                    exploit_summaries.append(ExploitSummary(
                        exploit_id=exploit.id or "unknown",
                        category=exploit.category,
                        severity=exploit.severity.value,
                        file_path=loc.file_path,
                        line_start=loc.line_start,
                        line_end=loc.line_end or loc.line_start,
                        description=exploit.description[:200]  # Truncate
                    ))
                    
                    # Add as code reference with priority based on severity
                    code_references.append(CodeReference(
                        file_path=loc.file_path,
                        line_start=loc.line_start,
                        line_end=loc.line_end or loc.line_start,
                        reason=f"{exploit.category} vulnerability",
                        priority=priority_map.get(exploit.severity.value, 5)
                    ))
                except Exception as e:
                    # Skip invalid exploits rather than crashing
                    pass
        
        # Calculate exploit stats for this agent
        exploit_stats = {}
        for exploit in exploits_found:
            severity = exploit.severity.value
            exploit_stats[severity] = exploit_stats.get(severity, 0) + 1
        
        # Aggregate sub-agent costs and exploits
        sub_agent_total_cost = 0.0
        sub_agent_total_tokens = {"prompt_tokens": 0, "completion_tokens": 0}
        sub_agent_exploits_count = 0
        sub_agent_exploit_stats = {}
        
        for sub_report in self.sub_agent_reports:
            if "budget_used" in sub_report:
                sub_agent_total_cost += sub_report["budget_used"].get("total_cost", 0.0)
                tokens = sub_report["budget_used"].get("tokens", {})
                sub_agent_total_tokens["prompt_tokens"] += tokens.get("prompt_tokens", 0)
                sub_agent_total_tokens["completion_tokens"] += tokens.get("completion_tokens", 0)
            if "exploits" in sub_report:
                exploits_list = sub_report["exploits"]
                sub_agent_exploits_count += len(exploits_list)
                # Aggregate exploit stats from sub-agents
                for exploit in exploits_list:
                    severity = exploit.get('severity', 'unknown')
                    sub_agent_exploit_stats[severity] = sub_agent_exploit_stats.get(severity, 0) + 1
        
        # Calculate combined totals (this agent + all sub-agents)
        combined_total_cost = self.estimated_cost + sub_agent_total_cost
        combined_total_tokens = {
            "prompt_tokens": self.total_tokens["prompt_tokens"] + sub_agent_total_tokens["prompt_tokens"],
            "completion_tokens": self.total_tokens["completion_tokens"] + sub_agent_total_tokens["completion_tokens"]
        }
        
        # Calculate combined exploit stats (this agent + all sub-agents)
        combined_exploit_stats = {}
        for severity, count in exploit_stats.items():
            combined_exploit_stats[severity] = combined_exploit_stats.get(severity, 0) + count
        for severity, count in sub_agent_exploit_stats.items():
            combined_exploit_stats[severity] = combined_exploit_stats.get(severity, 0) + count
        
        # Generate natural language summary
        summary = self._generate_summary_text(exploits_found, files_explored)
        
        # Calculate turns used
        turns_used = self.max_tool_turns - self._get_remaining_turns()
        
        # Determine completion status
        exploration_complete = turns_used < self.max_tool_turns  # Finished early
        requires_followup = len(code_references) > 0 or not exploration_complete
        
        # Convert messages to dict for nested conversation storage
        conversation_data = [msg.model_dump() for msg in self.messages]
        
        # Create structured report
        report = SubAgentReport(
            agent_id=self.agent_id,
            parent_agent_id=self.parent_agent_id,
            depth=self.depth,
            scope_path=self.scope_paths[0] if self.scope_paths else self.repo_path,
            task_description=self._extract_task_from_messages(),
            turns_used=turns_used,
            turns_allocated=self.max_tool_turns,
            # Budget tracking (this agent only)
            total_tokens=self.total_tokens,
            estimated_cost=self.estimated_cost,
            # Budget tracking (sub-agents only)
            sub_agent_total_tokens=sub_agent_total_tokens,
            sub_agent_total_cost=sub_agent_total_cost,
            # Budget tracking (combined)
            combined_total_tokens=combined_total_tokens,
            combined_total_cost=combined_total_cost,
            # Exploration results
            files_explored=files_explored,
            exploits_found=exploit_summaries,
            exploit_stats=exploit_stats,
            code_references=code_references[:10],  # Top 10
            # Sub-agent exploit tracking
            sub_agent_exploit_stats=sub_agent_exploit_stats,
            # Combined exploit stats
            combined_exploit_stats=combined_exploit_stats,
            sub_reports=self.sub_agent_reports,  # Nested reports
            summary=summary,
            exploration_complete=exploration_complete,
            requires_followup=requires_followup,
            conversation=conversation_data  # NEW: Full conversation for web viewer
        )
        
        return report

