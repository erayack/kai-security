import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

# Agent settings
MAX_TOOL_TURNS = 24
MAX_SUBAGENT_TURNS = 24
MAX_DEPTH = 2


def set_max_subagent_turns(turns: int) -> int:
    """
    Update the global sub-agent turn budget at runtime.
    Returns the sanitized value that was applied.
    """
    global MAX_SUBAGENT_TURNS
    sanitized = max(1, int(turns))
    MAX_SUBAGENT_TURNS = sanitized
    return sanitized

# Generator settings
GENERATOR_BATCH_SIZE = 1  # Number of exploits.json files to process in parallel

# Fixer settings
FIXER_BATCH_SIZE = 2  # Number of exploits.json files to process in parallel

# OpenRouter
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_STRONG_MODEL = "anthropic/claude-sonnet-4"
OPENROUTER_GEMINI_FLASH = "google/gemini-2.5-flash-preview-09-2025"

# OpenAI settings
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_STRONG_MODEL = "gpt-5-2025-08-07"

# vLLM
VLLM_HOST = os.getenv("VLLM_HOST", "0.0.0.0")
VLLM_PORT = int(os.getenv("VLLM_PORT", "8000"))

# Engine
# Increased timeout for depth-1 agents that spawn many sub-agents (can take 10+ minutes)
SANDBOX_TIMEOUT = 3600  # 1 hour

# Path settings
FINDER_AGENT_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "finder_agent_prompt.txt"
)
FINDER_SUBAGENT_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "finder_subagent_prompt.txt"
)
NON_DUPLICATE_VERIFIER_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "non_duplicate_verifier_prompt.txt"
)
TEST_GENERATOR_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "test_generator_prompt.txt"
)
GENERATOR_SUBAGENT_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "generator_subagent_prompt.txt"
)
SETUP_AGENT_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "setup_agent_prompt.txt"
)
FIXER_AGENT_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "fixer_agent_prompt.txt"
)
SAVE_CONVERSATION_PATH = "output/conversations/"
EXPLOITS_PATH = "exploits.json"
TEST_SCRIPTS_PATH = "test/"


## Logging settings
OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY")
MONGO_URI: str = os.getenv("MONGO_URI")
MONGO_DB_NAME: str = "kai"
