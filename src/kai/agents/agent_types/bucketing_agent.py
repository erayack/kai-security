"""
BucketingAgent: Categorizes functions into lens buckets for invariant generation.
"""

from typing import Any, Dict, List, Optional, Set

from kai.agents.base import BaseAgent
from kai.agents.utils import AgentType
from kai.schemas import AgentResponse
from kai.utils.dependency.adapters.base import LensDefinition


class BucketingAgent(BaseAgent):
    """
    Agent that categorizes functions into security-focused lens buckets.

    The agent uses LLM reasoning to assign each function to relevant lenses
    based on semantic understanding of the function's purpose and characteristics.
    """

    def __init__(
        self,
        functions: List[Dict[str, Any]],
        lens_definitions: List[LensDefinition],
        max_tool_turns: Optional[int] = None,
        repo_path: Optional[str] = None,
        use_vllm: bool = False,
        model: Optional[str] = None,
        use_openai: bool = False,
    ):
        """
        Initialize the BucketingAgent.

        Args:
            functions: List of function info dicts from GraphQueryEngine.get_functions_with_metadata()
            lens_definitions: List of LensDefinition from the adapter
            max_tool_turns: Maximum tool calling turns
            repo_path: Repository path
            use_vllm: Whether to use vLLM
            model: Model to use
            use_openai: Whether to use OpenAI directly
        """
        # Calculate max turns - with batching we need far fewer turns
        # Roughly 1 turn per 10-20 functions + overhead
        if max_tool_turns is None:
            max_tool_turns = min(len(functions) // 10 + 10, 30)

        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            agent_type=AgentType.BUCKETING,
            use_openai=use_openai,
        )

        # Store inputs
        self.functions = functions
        self.lens_definitions = lens_definitions

        # Initialize buckets
        self.available_lens_names: Set[str] = {lens.name for lens in lens_definitions}
        self.buckets: Dict[str, List[str]] = {
            lens.name: [] for lens in lens_definitions
        }

        # Tracking
        self.all_function_ids: Set[str] = {f["id"] for f in functions}
        self.assigned_functions: Set[str] = set()
        self.skipped_functions: Dict[str, str] = {}  # function_id -> reason
        self.bucketing_finalized: bool = False

    def build_task_message(self) -> str:
        """
        Build the task message with functions and lens definitions.
        """
        # Format lens definitions
        lens_desc_lines = []
        for lens in self.lens_definitions:
            lens_desc_lines.append(f"### {lens.name}")
            lens_desc_lines.append(f"**Description:** {lens.description}")
            lens_desc_lines.append(
                f"**Invariant Types:** {', '.join(lens.invariant_types)}"
            )
            lens_desc_lines.append("")

        lens_descriptions = "\n".join(lens_desc_lines)

        # Format functions (limit details to keep context manageable)
        func_lines = []
        for func in self.functions:
            func_lines.append(f"- **{func['id']}**")
            func_lines.append(f"  - Name: {func['name']}")
            func_lines.append(f"  - Container: {func.get('container', 'N/A')}")
            if func.get("meta"):
                meta = func["meta"]
                if meta.get("visibility"):
                    func_lines.append(f"  - Visibility: {meta['visibility']}")
                if meta.get("modifiers"):
                    func_lines.append(f"  - Modifiers: {meta['modifiers']}")
                if meta.get("is_payable"):
                    func_lines.append("  - Payable: True")
            if func.get("reads"):
                func_lines.append(
                    f"  - Reads: {func['reads'][:5]}{'...' if len(func['reads']) > 5 else ''}"
                )
            if func.get("writes"):
                func_lines.append(
                    f"  - Writes: {func['writes'][:5]}{'...' if len(func['writes']) > 5 else ''}"
                )
            func_lines.append("")

        functions_description = "\n".join(func_lines)

        return f"""## Lens Definitions

{lens_descriptions}

## Functions to Categorize ({len(self.functions)} total)

{functions_description}

## Instructions

IMPORTANT: Use BATCH assignments for efficiency!

1. Group functions by their lens assignments
2. Call `assign_to_lens(function_ids=[...], lens_names=[...])` with MULTIPLE function IDs at once
3. If functions don't fit any lens, call `skip_functions(function_ids=[...], reason="...")`
4. When ALL {len(self.functions)} functions are assigned, call `finalize_bucketing()`

Example of efficient batching:
```
assign_to_lens(function_ids=["func1", "func2", "func3"], lens_names=["economic"])
assign_to_lens(function_ids=["func4", "func5"], lens_names=["safety", "economic"])
```

Start now - group similar functions and assign them in batches.
"""

    def check_termination(self, response: str, python_code: str) -> bool:
        """
        BucketingAgent terminates when bucketing is finalized.
        """
        return self.bucketing_finalized

    def get_tools_module(self) -> str:
        """
        Get the tools module for bucketing agent.
        """
        return "kai.agents.tools.bucketing_tools"

    def extract_final_result(
        self, thoughts: str, python_code: str, response: str
    ) -> AgentResponse:
        """
        Extract the final result for bucketing agent.
        """
        return AgentResponse(
            thoughts=thoughts,
            python_block=python_code,
        )

    def get_buckets(self) -> Dict[str, List[str]]:
        """
        Get the final buckets after bucketing is complete.

        Returns:
            Dict mapping lens_name -> list of function_ids
        """
        return self.buckets
