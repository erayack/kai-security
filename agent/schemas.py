from enum import Enum
from typing import Optional, List

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

    def __str__(self):
        return f"Thoughts: {self.thoughts}\nPython block:\n {self.python_block}"

class GrepResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str

    def __str__(self):
        return f"- Exit code: {self.exit_code}\n- Stdout: {self.stdout}\n- Stderr: {self.stderr}"

class ExploitSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ExploitLocation(BaseModel):
    file_path: str
    line_start: int
    line_end: Optional[int] = None  # None if single line
    class_name: Optional[str] = None
    function_name: Optional[str] = None
    vulnerable_code: str  # The specific code at this location

class Exploit(BaseModel):
    category: str  # e.g., "SQL Injection", "Prototype Pollution", "Regex DoS", etc.
    severity: ExploitSeverity
    locations: List[ExploitLocation]  # All locations where this exploit appears
    description: str  # General description of the vulnerability pattern
    suggested_fix: Optional[str] = None  # General fix approach