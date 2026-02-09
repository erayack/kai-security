"""BountyBench task loading and metadata extraction."""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class BountyInfo:
    """Information about a single bounty within a BountyBench task."""

    bounty_id: str
    cwe: str  # e.g., "CWE-89"
    cve: str  # e.g., "CVE-2024-12345"
    severity: float  # e.g., 7.5
    exploit_prompt: str  # Description of vulnerability
    docker_compose_path: str | None
    verify_script_path: str | None
    exploit_files_path: str | None = None  # Path to exploit_files/ directory
    bounty_setup_hosts: list[str] = field(
        default_factory=list
    )  # e.g., ["django-app:8000"]
    verification_hints: list[str] = field(
        default_factory=list
    )  # Hints extracted from verify.sh
    patch_mappings: dict[str, str] = field(
        default_factory=dict
    )  # Maps patch file paths to target paths
    vulnerable_commit: str | None = None  # Git commit hash of vulnerable version
    compatible_exploits: list[str] = field(
        default_factory=list
    )  # List of compatible exploit IDs
    disclosure_bounty: float = 0.0  # USD value for vulnerability disclosure
    patch_bounty: float = 0.0  # USD value for providing a patch
    exploit_info: str = ""  # Exploit-specific context (credentials, known IDs)


class TaskLoader:
    """Load BountyBench task structure and extract metadata.

    BountyBench task structure:
        task_dir/
        ├── metadata.json           # target_host, invariant_thresholds
        ├── codebase/               # Source code
        ├── bounties/
        │   └── bounty_N/
        │       ├── bounty_metadata.json  # CWE, CVE, severity, exploit_prompt
        │       ├── setup_files/
        │       │   └── docker-compose.yml
        │       ├── exploit_files/
        │       └── verify_files/
        │           └── verify.sh
        └── *_auth.ini              # Credentials (optional)
    """

    def __init__(self, task_dir: str | Path):
        self.task_dir = Path(task_dir).resolve()
        self._metadata: dict | None = None
        self._bounties: dict[str, BountyInfo] | None = None

    def get_task_metadata(self) -> dict:
        """Load metadata.json from task directory."""
        if self._metadata is not None:
            return self._metadata

        metadata_path = self.task_dir / "metadata.json"
        if metadata_path.exists():
            with open(metadata_path) as f:
                self._metadata = json.load(f)
        else:
            logger.warning(f"No metadata.json found at {metadata_path}")
            self._metadata = {}

        return self._metadata

    def list_bounties(self) -> list[str]:
        """List bounty_N directories."""
        bounties_dir = self.task_dir / "bounties"
        if not bounties_dir.exists():
            return []

        bounty_dirs = sorted(
            (
                d.name
                for d in bounties_dir.iterdir()
                if d.is_dir() and d.name.startswith("bounty_")
            ),
            key=lambda x: int(x.split("_")[-1]) if x.split("_")[-1].isdigit() else x,
        )
        return bounty_dirs

    def _extract_verification_hints(self, verify_script_path: str | None) -> list[str]:
        """Extract verification hints from verify.sh script.

        Parses the verify script to understand what output/behavior the
        verifier expects, which helps guide exploit development.

        Args:
            verify_script_path: Path to verify.sh script

        Returns:
            List of hint strings describing expected outputs
        """
        hints: list[str] = []

        if not verify_script_path:
            return hints

        try:
            verify_content = Path(verify_script_path).read_text()
        except Exception as e:
            logger.warning(f"Failed to read verify script: {e}")
            return hints

        # Look for grep patterns (what the verifier expects in output)
        # Common patterns: grep -q "pattern" or grep "pattern"
        grep_patterns = re.findall(
            r'grep\s+(?:-[a-zA-Z]+\s+)*["\']([^"\']+)["\']', verify_content
        )
        for pattern in grep_patterns:
            hints.append(f"Exploit must produce output containing: '{pattern}'")

        # Look for file existence checks: -f "file" or -s "file"
        file_checks = re.findall(r'-[fs]\s+["\']?([^"\')\s]+)["\']?', verify_content)
        for file in file_checks:
            if not file.startswith("-"):  # Avoid matching flags
                hints.append(f"Exploit must create file: {file}")

        # Look for specific error types mentioned
        error_types = re.findall(
            r"((?:Error|Exception|RangeError|TypeError|SyntaxError)[^\"']*)",
            verify_content,
        )
        for error_type in error_types:
            if len(error_type) > 5:  # Avoid short matches
                hints.append(f"Expected error type: {error_type.strip()}")

        # Look for exit code checks
        exit_checks = re.findall(r"exit\s+(\d+)", verify_content)
        if exit_checks:
            # Find context around exit statements
            for match in re.finditer(
                r'(?:echo\s+["\']([^"\']+)["\'].*?\n\s*)?exit\s+0', verify_content
            ):
                if match.group(1):
                    hints.append(f"Success condition: {match.group(1)}")

        return hints

    def load_bounty(self, bounty_id: str) -> BountyInfo:
        """Load bounty metadata and paths."""
        bounty_dir = self.task_dir / "bounties" / bounty_id

        # Load bounty_metadata.json
        metadata_path = bounty_dir / "bounty_metadata.json"
        if metadata_path.exists():
            with open(metadata_path) as f:
                metadata = json.load(f)
        else:
            metadata = {}
            logger.warning(f"No bounty_metadata.json found for {bounty_id}")

        # Find docker-compose file
        docker_compose_path = None
        setup_files = bounty_dir / "setup_files"
        if setup_files.exists():
            for name in ["docker-compose.yml", "docker-compose.yaml"]:
                candidate = setup_files / name
                if candidate.exists():
                    docker_compose_path = str(candidate)
                    break

        # Find verify script
        verify_script_path = None
        verify_files = bounty_dir / "verify_files"
        if verify_files.exists():
            verify_sh = verify_files / "verify.sh"
            if verify_sh.exists():
                verify_script_path = str(verify_sh)

        # Fallback: check bounty root for verify.sh
        if not verify_script_path:
            verify_sh = bounty_dir / "verify.sh"
            if verify_sh.exists():
                verify_script_path = str(verify_sh)

        # Find exploit_files directory (where verify.sh expects error.log)
        exploit_files_path = None
        exploit_files = bounty_dir / "exploit_files"
        if exploit_files.exists():
            exploit_files_path = str(exploit_files)
        else:
            # Create it if it doesn't exist - verify.sh needs it
            exploit_files.mkdir(parents=True, exist_ok=True)
            exploit_files_path = str(exploit_files)

        # Extract setup hosts from metadata
        bounty_setup_hosts = metadata.get("bounty_setup_hosts", [])

        # Extract verification hints from verify.sh
        verification_hints = self._extract_verification_hints(verify_script_path)

        # Extract patch mappings (for Detect Indicator evaluation)
        patch_mappings = metadata.get("patch", {})

        # Extract vulnerable commit hash
        vulnerable_commit = metadata.get("vulnerable_commit")

        # Extract compatible exploits list
        compatible_exploits = metadata.get("compatible_exploits", [])

        # Extract exploit-specific context (credentials, known IDs)
        exploit_info = metadata.get("exploit_info", "")

        return BountyInfo(
            bounty_id=bounty_id,
            # Case-insensitive fallback for CWE/CVE (some metadata uses uppercase)
            cwe=metadata.get("CWE", metadata.get("cwe", "")),
            cve=metadata.get("CVE", metadata.get("cve", "")),
            severity=float(metadata.get("severity", 0.0)),
            exploit_prompt=metadata.get("exploit_prompt", ""),
            docker_compose_path=docker_compose_path,
            verify_script_path=verify_script_path,
            exploit_files_path=exploit_files_path,
            bounty_setup_hosts=bounty_setup_hosts,
            verification_hints=verification_hints,
            patch_mappings=patch_mappings,
            vulnerable_commit=vulnerable_commit,
            compatible_exploits=compatible_exploits,
            disclosure_bounty=float(metadata.get("disclosure_bounty") or 0),
            patch_bounty=float(metadata.get("patch_bounty") or 0),
            exploit_info=exploit_info,
        )

    def get_all_bounties(self) -> list[BountyInfo]:
        """Load all bounties."""
        if self._bounties is not None:
            return list(self._bounties.values())

        self._bounties = {}
        for bounty_id in self.list_bounties():
            self._bounties[bounty_id] = self.load_bounty(bounty_id)

        return list(self._bounties.values())

    def get_codebase_path(self) -> str:
        """Return path to codebase/ directory."""
        codebase_path = self.task_dir / "codebase"
        if codebase_path.exists():
            return str(codebase_path)

        # Fallback to task_dir if no codebase subdirectory
        return str(self.task_dir)

    def get_target_host(self) -> str | None:
        """Extract target_host from metadata or infer from docker."""
        metadata = self.get_task_metadata()

        # Check metadata.json first
        if "target_host" in metadata:
            return metadata["target_host"]

        # Try to infer from bounty setup hosts
        bounties = self.get_all_bounties()
        for bounty in bounties:
            if bounty.bounty_setup_hosts:
                # Return the first host as target
                host = bounty.bounty_setup_hosts[0]
                # Convert internal docker hostname to localhost
                if ":" in host:
                    port = host.split(":")[-1]
                    return f"http://localhost:{port}"

        return None

    def get_task_name(self) -> str:
        """Get the task name from directory name."""
        return self.task_dir.name

    def build_extra_instructions(self) -> str:
        """Build extra_instructions string from all bounty metadata.

        Includes:
        - CWE IDs and descriptions
        - exploit_prompt text from each bounty
        - Target host URL
        - Credentials (if available)
        """
        lines: list[str] = []

        lines.append("## BountyBench Task Information")
        lines.append("")

        # Task metadata
        metadata = self.get_task_metadata()
        if metadata:
            lines.append("### Task Metadata")
            if "description" in metadata:
                lines.append(f"Description: {metadata['description']}")
            lines.append("")

        # Task context info (credentials, setup instructions) from metadata.json
        if metadata and "info" in metadata:
            lines.append("### Task Context")
            lines.append(metadata["info"])
            lines.append("")

        # Target host
        target_host = self.get_target_host()
        if target_host:
            lines.append("### Target Host")
            lines.append(f"Target URL: {target_host}")
            lines.append("")

        # Bounty information
        bounties = self.get_all_bounties()
        if bounties:
            lines.append("### Bounty Information")
            lines.append("")

            for bounty in bounties:
                lines.append(f"#### {bounty.bounty_id}")

                if bounty.cwe:
                    lines.append(f"- CWE: {bounty.cwe}")
                if bounty.cve:
                    lines.append(f"- CVE: {bounty.cve}")
                if bounty.severity > 0:
                    lines.append(f"- Severity: {bounty.severity}")

                if bounty.exploit_prompt:
                    lines.append("")
                    lines.append("**Exploit Hint:**")
                    lines.append(bounty.exploit_prompt)

                if bounty.exploit_info:
                    lines.append("")
                    lines.append("**Exploit Context:**")
                    lines.append(bounty.exploit_info)

                # Add verification hints from verify.sh
                if bounty.verification_hints:
                    lines.append("")
                    lines.append("**Verification Requirements:**")
                    for hint in bounty.verification_hints:
                        lines.append(f"- {hint}")

                lines.append("")

        return "\n".join(lines)
