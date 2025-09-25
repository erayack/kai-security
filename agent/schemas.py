from enum import Enum
from typing import Optional

from pydantic import BaseModel

class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"

class ChatMessage(BaseModel):
    role: Role
    content: str

class AgentResponse(BaseModel):
    thoughts: str
    python_block: Optional[str] = None
    reply: Optional[str] = None

    def __str__(self):
        return f"Thoughts: {self.thoughts}\nPython block:\n {self.python_block}\nReply: {self.reply}"

class GrepResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str

    def __str__(self):
        return f"- Exit code: {self.exit_code}\n- Stdout: {self.stdout}\n- Stderr: {self.stderr}"