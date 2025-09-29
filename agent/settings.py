import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

# Agent settings
MAX_TOOL_TURNS = 32

# OpenRouter
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_STRONG_MODEL = "anthropic/claude-sonnet-4"

# vLLM
VLLM_HOST = os.getenv("VLLM_HOST", "0.0.0.0")
VLLM_PORT = int(os.getenv("VLLM_PORT", "8000"))

# Engine
SANDBOX_TIMEOUT = 20

# Path settings
FINDER_AGENT_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "finder_agent_prompt.txt"
SAVE_CONVERSATION_PATH = "output/conversations/"