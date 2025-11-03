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
OPENROUTER_GEMINI_FLASH = "google/gemini-2.5-flash-preview-09-2025"

# OpenAI settings
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_STRONG_MODEL = "gpt-5-2025-08-07"

# vLLM
VLLM_HOST = os.getenv("VLLM_HOST", "0.0.0.0")
VLLM_PORT = int(os.getenv("VLLM_PORT", "8000"))

# Engine
SANDBOX_TIMEOUT = 200 

# Path settings
FINDER_AGENT_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "finder_agent_prompt.txt"
FINDER_SUBAGENT_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "finder_subagent_prompt.txt"
NON_DUPLICATE_VERIFIER_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "non_duplicate_verifier_prompt.txt"
TEST_GENERATOR_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "test_generator_prompt.txt"
SETUP_AGENT_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "setup_agent_prompt.txt"
FIXER_AGENT_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "fixer_agent_prompt.txt"
SAVE_CONVERSATION_PATH = "output/conversations/"
EXPLOITS_PATH = "exploits.json"
TEST_SCRIPTS_PATH = "test/"