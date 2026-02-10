"""
Canonical framework detection — single source of truth.

All call sites that need to detect a build/test framework should delegate
to ``detect_framework()`` rather than rolling their own heuristics.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from kai.utils.tool_adapters import get_supported_frameworks

# Canonical map: mc.adapter (language) → tool framework
ADAPTER_TO_FRAMEWORK: dict[str, str] = {
    "solidity": "foundry",
    "javascript": "javascript",
    "typescript": "typescript",
    "python": "python",
    "c": "c",
}

# Inverse of ADAPTER_TO_FRAMEWORK, plus common aliases
FRAMEWORK_TO_ADAPTER: dict[str, str] = {
    "foundry": "solidity",
    "forge": "solidity",
    "hardhat": "solidity",
    "python": "python",
    "py": "python",
    "uv": "python",
    "pip": "python",
    "poetry": "python",
    "typescript": "typescript",
    "ts": "typescript",
    "javascript": "javascript",
    "js": "javascript",
    "node": "javascript",
    "npm": "javascript",
    "yarn": "javascript",
    "pnpm": "javascript",
    "c": "c",
    "cmake": "c",
    "make": "c",
    "gcc": "c",
}


def detect_framework(
    workspace: Path,
    *,
    adapter: Optional[str] = None,
    frameworks: Optional[list[str]] = None,
) -> Optional[str]:
    """
    Detect the build/test framework for a workspace.

    Args:
        workspace: Path to the project root
        adapter: MasterContext.adapter value (language, e.g. "solidity")
        frameworks: MasterContext.frameworks list

    Returns:
        Framework name or None if detection fails
    """
    supported = set(get_supported_frameworks())

    # 1. Trust mc.adapter if it maps to a supported framework
    #    BUT don't trust "solidity" default without foundry.toml
    if adapter:
        adapter_lower = adapter.lower()
        if adapter_lower == "solidity" and not (workspace / "foundry.toml").exists():
            pass  # fall through
        else:
            mapped = ADAPTER_TO_FRAMEWORK.get(adapter_lower, adapter_lower)
            if mapped in supported:
                return mapped

    # 2. Check frameworks list (from setup LLM)
    if frameworks:
        for fw in frameworks:
            fw_lower = str(fw).lower()
            if fw_lower == "forge":
                fw_lower = "foundry"
            if fw_lower in supported:
                return fw_lower

    # 3. Config-file detection
    if (workspace / "foundry.toml").exists() and "foundry" in supported:
        return "foundry"
    if (workspace / "Cargo.toml").exists() and "cargo" in supported:
        return "cargo"
    if (workspace / "CMakeLists.txt").exists() and "cmake" in supported:
        return "cmake"
    if (workspace / "tsconfig.json").exists() and "typescript" in supported:
        return "typescript"
    if (workspace / "package.json").exists():
        # Check for TS files even without tsconfig
        if "typescript" in supported and (
            any(workspace.glob("**/*.ts")) or any(workspace.glob("**/*.tsx"))
        ):
            return "typescript"
        if "javascript" in supported:
            return "javascript"
    if "python" in supported and (
        (workspace / "pyproject.toml").exists()
        or (workspace / "setup.py").exists()
        or (workspace / "requirements.txt").exists()
    ):
        return "python"

    # 4. Makefile-based C detection (before extension fallback so it wins
    #    over stray .c files in non-C projects)
    if "c" in supported and (
        (workspace / "Makefile").exists()
        or (workspace / "configure").exists()
        or (workspace / "meson.build").exists()
    ):
        return "c"

    # 5. Shallow file-extension fallbacks
    if any(workspace.glob("*.sol")) and "foundry" in supported:
        return "foundry"
    if any(workspace.glob("*.rs")) and "cargo" in supported:
        return "cargo"
    if "c" in supported and any(
        any(workspace.glob(f"**/*{ext}")) for ext in (".c", ".cpp", ".cc", ".cxx")
    ):
        return "c"

    return None  # No silent "foundry" default
