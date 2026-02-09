"""
Centralized framework detection for Kai.

Consolidates framework detection logic that was previously duplicated across:
- dispatcher/workspace.py
- processes/workspace_validation.py
- agents/tools/setup_tools.py
- agents/tools/shared.py

Detection priority (highest to lowest):
1. Config files: pyproject.toml, setup.py, requirements.txt, foundry.toml, etc.
2. MasterContext.frameworks list (set by SetupAgent)
3. MasterContext.adapter value (only non-default values)
"""

from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from kai.schemas import MasterContext


class FrameworkDetector:
    """
    Centralized framework detection.

    Detects the build/test framework for a project by inspecting config files
    and MasterContext metadata. Raises ValueError when detection fails instead
    of silently defaulting to Foundry.
    """

    # Map domain adapter names to tool framework names
    ADAPTER_TO_FRAMEWORK = {
        "solidity": "foundry",
        "javascript": "javascript",
        "typescript": "javascript",
        "python": "python",
        "c": "c",
    }

    @classmethod
    def detect_framework(
        cls,
        path: Path,
        master_context: Optional["MasterContext"] = None,
    ) -> str:
        """
        Detect the build/test framework for a project.

        Priority:
        1. MasterContext.adapter (only non-default values, i.e. not "solidity")
        2. MasterContext.frameworks (first supported match)
        3. Config file detection

        Args:
            path: Path to the project root
            master_context: Optional MasterContext with framework info

        Returns:
            Framework name (e.g., "foundry", "python", "javascript", "cargo", "cmake", "c")

        Raises:
            ValueError: If no framework can be detected
        """
        from kai.utils.tool_adapters import get_supported_frameworks

        supported = set(get_supported_frameworks())

        # 1. Check MasterContext.adapter (only non-default values)
        if master_context:
            adapter = getattr(master_context, "adapter", None)
            if adapter:
                adapter_lower = str(adapter).lower()
                # Don't trust "solidity" default if there's no foundry.toml
                # (MasterContext.adapter defaults to "solidity")
                if adapter_lower == "solidity" and not (path / "foundry.toml").exists():
                    pass  # Fall through to other detection
                else:
                    mapped = cls.ADAPTER_TO_FRAMEWORK.get(adapter_lower, adapter_lower)
                    if mapped in supported:
                        return mapped

        # 2. Check MasterContext.frameworks
        if master_context:
            frameworks = getattr(master_context, "frameworks", None) or []
            for fw in frameworks:
                fw_lower = str(fw).lower()
                if fw_lower == "forge":
                    fw_lower = "foundry"
                if fw_lower in supported:
                    return fw_lower

        # 3. Config file detection
        detected = cls._detect_from_config_files(path, supported)
        if detected:
            return detected

        raise ValueError(
            f"Cannot detect framework for {path}. "
            f"No config files found and no framework specified in MasterContext. "
            f"Supported frameworks: {', '.join(sorted(supported))}"
        )

    @classmethod
    def detect_framework_with_fallback(
        cls,
        path: Path,
        master_context: Optional["MasterContext"] = None,
        fallback: str = "foundry",
    ) -> str:
        """
        Detect framework with a fallback value instead of raising.

        Use this when a default is acceptable (e.g., legacy code paths).
        """
        try:
            return cls.detect_framework(path, master_context)
        except ValueError:
            return fallback

    @staticmethod
    def _detect_from_config_files(path: Path, supported: set) -> Optional[str]:
        """
        Detect framework from config files in the project directory.

        Returns:
            Framework name or None if not detected
        """
        # Foundry
        if (path / "foundry.toml").exists() and "foundry" in supported:
            return "foundry"

        # Cargo (Rust)
        if (path / "Cargo.toml").exists() and "cargo" in supported:
            return "cargo"

        # CMake
        if (path / "CMakeLists.txt").exists() and "cmake" in supported:
            return "cmake"

        # TypeScript (check before JavaScript since TS projects also have package.json)
        if (path / "tsconfig.json").exists() and "typescript" in supported:
            return "typescript"

        # JavaScript/TypeScript via package.json
        if (path / "package.json").exists() and "javascript" in supported:
            # Check if it's a TypeScript project
            if "typescript" in supported:
                if (path / "tsconfig.json").exists():
                    return "typescript"
                try:
                    if any(path.glob("**/*.ts")) or any(path.glob("**/*.tsx")):
                        return "typescript"
                except Exception:
                    pass
            return "javascript"

        # Python (check pyproject.toml, setup.py, requirements.txt in order)
        if "python" in supported:
            if (path / "pyproject.toml").exists():
                return "python"
            if (path / "setup.py").exists():
                return "python"
            if (path / "requirements.txt").exists():
                return "python"

        # Hardhat (JS-based Solidity)
        if (
            (path / "hardhat.config.js").exists()
            or (path / "hardhat.config.ts").exists()
        ) and "hardhat" in supported:
            return "hardhat"

        # Shallow fallback: file extension heuristics
        try:
            if any(path.glob("*.sol")) and "foundry" in supported:
                return "foundry"
        except Exception:
            pass

        try:
            if any(path.glob("*.rs")) and "cargo" in supported:
                return "cargo"
        except Exception:
            pass

        if "cmake" in supported or "c" in supported:
            cpp_suffixes = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"}
            try:
                if any(
                    p.is_file() and p.suffix.lower() in cpp_suffixes
                    for p in path.iterdir()
                ):
                    return "c" if "c" in supported else "cmake"
            except Exception:
                pass

        return None


def detect_framework(
    path: Path,
    master_context: Optional["MasterContext"] = None,
) -> str:
    """
    Convenience function wrapping FrameworkDetector.detect_framework().

    Raises ValueError if detection fails.
    """
    return FrameworkDetector.detect_framework(path, master_context)


def detect_framework_safe(
    path: Path,
    master_context: Optional["MasterContext"] = None,
    fallback: str = "foundry",
) -> str:
    """
    Convenience function wrapping FrameworkDetector.detect_framework_with_fallback().

    Returns fallback instead of raising.
    """
    return FrameworkDetector.detect_framework_with_fallback(
        path, master_context, fallback
    )
