"""BountyBench verification using verify.sh scripts.

This module runs BountyBench's verification scripts to confirm that
generated exploits successfully demonstrate the vulnerability.
"""

import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.bountybench_adapter.docker_manager import DockerManager
    from evaluation.bountybench_adapter.task_loader import TaskLoader

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of verifying an exploit against a bounty."""

    bounty_id: str
    success: bool
    exploit_output: str
    verify_output: str
    exploit_exit_code: int = 0
    verify_exit_code: int = 0
    error: str | None = None


@dataclass
class ExploitResult:
    """Intermediate result from running just the exploit."""

    success: bool
    output: str
    exit_code: int
    error: str | None = None


@dataclass
class ValidationResult:
    """Result of validating an exploit script before execution."""

    success: bool
    warnings: list[str] | None = None
    error: str | None = None


class BountyVerifier:
    """Run BountyBench verification scripts.

    The verification process:
    1. Execute exploit.sh with TARGET_HOST environment variable
    2. Execute verify.sh from bounty's verify_files/
    3. Return result based on exit codes
    """

    def __init__(
        self,
        task_loader: "TaskLoader",
        docker_manager: "DockerManager | None" = None,
        exploit_timeout: int = 30,
        verify_timeout: int = 30,
    ):
        """Initialize verifier.

        Args:
            task_loader: TaskLoader for accessing bounty metadata
            docker_manager: DockerManager for getting service URLs
            exploit_timeout: Timeout for exploit execution in seconds
            verify_timeout: Timeout for verify.sh execution in seconds
        """
        self.task_loader = task_loader
        self.docker_manager = docker_manager
        self.exploit_timeout = exploit_timeout
        self.verify_timeout = verify_timeout

    def _get_target_host(self) -> str:
        """Get target host URL for exploit execution."""
        # First try from task loader
        host = self.task_loader.get_target_host()
        if host:
            return host

        # Then try from docker manager
        if self.docker_manager:
            urls = self.docker_manager.get_service_urls()
            if urls:
                # Return the first service URL
                return next(iter(urls.values()))

        # Default fallback
        return "http://localhost:8080"

    def _validate_script_compatibility(
        self, script_path: Path
    ) -> ValidationResult:
        """Check for common cross-platform issues before execution.

        This validates the exploit script for:
        1. GNU-only mktemp flags that fail on macOS
        2. Hardcoded ports that won't match TARGET_HOST
        3. Host-side verification file creation (should be server-side)

        Args:
            script_path: Path to the exploit script

        Returns:
            ValidationResult with any issues found
        """
        if not script_path.exists():
            return ValidationResult(
                success=False,
                error=f"Script not found: {script_path}",
            )

        try:
            content = script_path.read_text()
        except Exception as e:
            return ValidationResult(
                success=False,
                error=f"Failed to read script: {e}",
            )

        warnings = []
        errors = []

        # Check for GNU-only mktemp (--suffix flag)
        if "mktemp --suffix" in content:
            if platform.system() == "Darwin":
                errors.append(
                    "Script uses GNU mktemp --suffix which fails on macOS. "
                    "Use cross-platform: mktemp /tmp/exploit_XXXXXX.ext"
                )
            else:
                warnings.append(
                    "Script uses GNU mktemp --suffix - may fail on macOS"
                )

        # Check for hardcoded ports in Python code
        hardcoded_port_patterns = [
            r'port\s*=\s*\d{4,5}\s*[#\n]',  # port = 9331
            r's\.connect\s*\(\s*\([^)]+,\s*\d{4,5}\s*\)',  # s.connect((host, 9331))
        ]
        for pattern in hardcoded_port_patterns:
            if re.search(pattern, content):
                warnings.append(
                    "Script may have hardcoded port - ensure it parses TARGET_HOST"
                )
                break

        # Check for host-side verification file creation
        verification_file_patterns = [
            r'open\s*\(\s*["\']\/tmp\/[^"\']+["\'].*["\']w["\']',  # open("/tmp/...", "w")
            r'with\s+open\s*\(\s*["\']\/tmp\/[^"\']+["\'].*["\']w["\']',  # with open("/tmp/...", "w")
        ]
        for pattern in verification_file_patterns:
            if re.search(pattern, content):
                warnings.append(
                    "Script creates verification files on HOST - "
                    "verify.sh checks INSIDE container via docker exec"
                )
                break

        if errors:
            return ValidationResult(
                success=False,
                warnings=warnings if warnings else None,
                error="; ".join(errors),
            )

        return ValidationResult(
            success=True,
            warnings=warnings if warnings else None,
        )

    def _run_exploit(
        self,
        exploit_script_path: str | Path,
        target_host: str,
    ) -> ExploitResult:
        """Run an exploit script.

        If a DockerManager is available, runs the exploit inside a Docker
        container on shared_net with Docker internal hostnames. Otherwise
        falls back to host execution.

        Args:
            exploit_script_path: Path to the exploit.sh script
            target_host: Target host URL (used for host execution fallback)

        Returns:
            ExploitResult with execution details
        """
        script_path = Path(exploit_script_path)
        if not script_path.exists():
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=f"Exploit script not found: {script_path}",
            )

        # Validate script compatibility before execution
        validation = self._validate_script_compatibility(script_path)
        if not validation.success:
            logger.error(f"Script validation failed: {validation.error}")
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=f"Script validation failed: {validation.error}",
            )
        if validation.warnings:
            for warning in validation.warnings:
                logger.warning(f"Script validation warning: {warning}")

        # Try Docker execution first if docker_manager is available
        if self.docker_manager:
            result = self._run_exploit_in_docker(script_path, target_host)
            if result is not None:
                return result
            logger.warning("Docker execution failed, falling back to host execution")

        # Fallback: host execution
        return self._run_exploit_on_host(script_path, target_host)

    def _run_exploit_in_docker(
        self,
        script_path: Path,
        target_host: str,
    ) -> ExploitResult | None:
        """Run exploit script inside a Docker container on shared_net.

        Creates a temporary container connected to shared_net, mounts the
        exploit directory, and executes the script with Docker internal
        hostnames as TARGET_HOST.

        Args:
            script_path: Path to the exploit script
            target_host: Host-side target URL (used to match the correct port)

        Returns:
            ExploitResult if Docker execution succeeded (even if exploit failed),
            None if Docker execution itself failed (caller should fall back to host)
        """
        assert self.docker_manager is not None
        internal_urls = self.docker_manager.get_internal_service_urls()
        if not internal_urls:
            logger.warning("No Docker internal URLs available for exploit execution")
            return None

        # Match the port from the host-side target_host to find the correct
        # internal URL.  e.g. target_host="http://localhost:3333" → pick the
        # internal URL whose container port is 3333, like "http://lunary-app:3333".
        docker_target_host = ""
        target_port: str | None = None
        if ":" in target_host:
            target_port = target_host.rsplit(":", 1)[-1].rstrip("/")

        if target_port:
            # Look for an internal URL matching the same container port
            for name, url in internal_urls.items():
                if url.endswith(f":{target_port}"):
                    docker_target_host = url
                    logger.info(f"Matched target port {target_port} → {url}")
                    break

        # Fallback: pick first non-DB service
        if not docker_target_host:
            db_services = {"postgres", "postgresql", "mysql", "mariadb", "redis",
                           "mongo", "mongodb", "memcached"}
            for name, url in internal_urls.items():
                base_name = name.split(":")[0]
                if base_name not in db_services:
                    docker_target_host = url
                    break

        if not docker_target_host:
            docker_target_host = next(iter(internal_urls.values()))

        logger.info(f"Running exploit in Docker with TARGET_HOST={docker_target_host}")

        exploit_dir = str(script_path.parent.resolve())
        script_name = script_path.name

        # Allow extra time: image pull (~30s if cached) + pip install (~30s) + exploit
        docker_timeout = self.exploit_timeout + 120

        try:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "--network", "shared_net",
                    "-v", f"{exploit_dir}:/app",
                    "-e", f"TARGET_HOST={docker_target_host}",
                    "-w", "/app",
                    "python:3.12-slim",
                    "bash", "-c",
                    "pip install requests > /dev/null 2>&1; "
                    f"bash /app/{script_name}",
                ],
                capture_output=True,
                text=True,
                timeout=docker_timeout,
            )

            output = result.stdout + result.stderr

            return ExploitResult(
                success=result.returncode == 0,
                output=output,
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=f"Docker exploit timed out after {docker_timeout}s",
            )
        except FileNotFoundError:
            logger.warning("Docker command not found, cannot run exploit in container")
            return None
        except Exception as e:
            logger.error(f"Docker exploit execution failed: {type(e).__name__}: {e}")
            return None

    def _run_exploit_on_host(
        self,
        script_path: Path,
        target_host: str,
    ) -> ExploitResult:
        """Run exploit script directly on the host (fallback).

        Args:
            script_path: Path to the exploit script
            target_host: Target host URL

        Returns:
            ExploitResult with execution details
        """
        env = os.environ.copy()
        env["TARGET_HOST"] = target_host

        try:
            result = subprocess.run(
                ["bash", str(script_path)],
                capture_output=True,
                text=True,
                timeout=self.exploit_timeout,
                env=env,
                cwd=script_path.parent,
            )

            output = result.stdout + result.stderr

            return ExploitResult(
                success=result.returncode == 0,
                output=output,
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=f"Exploit timed out after {self.exploit_timeout}s",
            )
        except Exception as e:
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=str(e),
            )

    def _ensure_pip_available(self, env: dict[str, str]) -> str | None:
        """Ensure `pip` is on PATH, creating a uv-backed wrapper if needed.

        BountyBench verify.sh scripts call `pip install ...` but some
        environments only have `uv`. This creates a temporary `pip` wrapper
        that delegates to `uv pip` and prepends it to PATH.

        Args:
            env: Environment dict (modified in-place with updated PATH)

        Returns:
            Path to temporary directory (caller should clean up), or None
        """
        # Check if pip already exists
        if shutil.which("pip", path=env.get("PATH")):
            return None

        # Check if uv exists
        if not shutil.which("uv", path=env.get("PATH")):
            logger.warning("Neither pip nor uv found on PATH")
            return None

        # Create a temporary directory with a pip wrapper
        tmp_dir = tempfile.mkdtemp(prefix="pip_shim_")
        pip_path = os.path.join(tmp_dir, "pip")

        with open(pip_path, "w") as f:
            f.write('#!/bin/sh\nexec uv pip "$@"\n')
        os.chmod(pip_path, os.stat(pip_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        # Also create pip3 wrapper
        pip3_path = os.path.join(tmp_dir, "pip3")
        with open(pip3_path, "w") as f:
            f.write('#!/bin/sh\nexec uv pip "$@"\n')
        os.chmod(pip3_path, os.stat(pip3_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        # Prepend to PATH
        env["PATH"] = tmp_dir + os.pathsep + env.get("PATH", "")
        logger.info(f"Created pip→uv shim at {tmp_dir}")

        return tmp_dir

    def _run_verify(
        self,
        bounty_id: str,
        target_host: str,
    ) -> ExploitResult:
        """Run the verify.sh script for a bounty.

        Args:
            bounty_id: Bounty identifier
            target_host: Target host URL

        Returns:
            ExploitResult with verification details
        """
        bounty = self.task_loader.load_bounty(bounty_id)

        if not bounty.verify_script_path:
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=f"No verify.sh found for {bounty_id}",
            )

        verify_path = Path(bounty.verify_script_path)
        if not verify_path.exists():
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=f"Verify script not found: {verify_path}",
            )

        env = os.environ.copy()
        env["TARGET_HOST"] = target_host

        # Ensure pip is available (verify.sh scripts often call `pip install`)
        pip_shim_dir = self._ensure_pip_available(env)

        try:
            result = subprocess.run(
                ["bash", str(verify_path)],
                capture_output=True,
                text=True,
                timeout=self.verify_timeout,
                env=env,
                cwd=verify_path.parent,
            )

            output = result.stdout + result.stderr

            return ExploitResult(
                success=result.returncode == 0,
                output=output,
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=f"Verify script timed out after {self.verify_timeout}s",
            )
        except Exception as e:
            return ExploitResult(
                success=False,
                output="",
                exit_code=-1,
                error=str(e),
            )
        finally:
            # Cleanup pip shim directory
            if pip_shim_dir:
                shutil.rmtree(pip_shim_dir, ignore_errors=True)

    def _copy_error_log_to_bounty(
        self,
        exploit_script_path: str | Path,
        bounty_id: str,
    ) -> bool:
        """Copy error.log from exploit directory to bounty's exploit_files directory.

        BountyBench verify.sh scripts expect error.log at ../exploit_files/error.log
        relative to verify_files/. This method bridges the gap between where our
        generated exploit scripts write error.log and where verify.sh looks for it.

        Args:
            exploit_script_path: Path to the exploit script (error.log is in same dir)
            bounty_id: Bounty identifier to get exploit_files path

        Returns:
            True if error.log was copied successfully, False otherwise
        """
        script_path = Path(exploit_script_path)
        source_error_log = script_path.parent / "error.log"

        if not source_error_log.exists():
            logger.warning(f"No error.log found at {source_error_log}")
            return False

        bounty = self.task_loader.load_bounty(bounty_id)
        if not bounty.exploit_files_path:
            logger.warning(f"No exploit_files path for {bounty_id}")
            return False

        dest_error_log = Path(bounty.exploit_files_path) / "error.log"

        try:
            # Ensure destination directory exists
            dest_error_log.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_error_log, dest_error_log)
            logger.info(f"Copied error.log to {dest_error_log}")
            return True
        except Exception as e:
            logger.warning(f"Failed to copy error.log: {e}")
            return False

    def verify_bounty(
        self,
        bounty_id: str,
        exploit_script_path: str | Path,
        target_host: str | None = None,
    ) -> VerificationResult:
        """Run exploit.sh then verify.sh for a bounty.

        Args:
            bounty_id: Bounty identifier to verify
            exploit_script_path: Path to the exploit.sh script
            target_host: Target host URL (auto-detected if not provided)

        Returns:
            VerificationResult with exploit and verify outputs
        """
        host = target_host or self._get_target_host()

        logger.info(f"Verifying {bounty_id} against {host}")

        # Run exploit
        exploit_result = self._run_exploit(exploit_script_path, host)

        if exploit_result.error:
            return VerificationResult(
                bounty_id=bounty_id,
                success=False,
                exploit_output=exploit_result.output,
                verify_output="",
                exploit_exit_code=exploit_result.exit_code,
                error=f"Exploit error: {exploit_result.error}",
            )

        # Copy error.log to where verify.sh expects it
        # (BountyBench verify.sh looks for ../exploit_files/error.log)
        self._copy_error_log_to_bounty(exploit_script_path, bounty_id)

        # Run verify.sh regardless of exploit exit code
        # (some exploits may "fail" but still trigger the vulnerability)
        verify_result = self._run_verify(bounty_id, host)

        if verify_result.error:
            return VerificationResult(
                bounty_id=bounty_id,
                success=False,
                exploit_output=exploit_result.output,
                verify_output=verify_result.output,
                exploit_exit_code=exploit_result.exit_code,
                verify_exit_code=verify_result.exit_code,
                error=f"Verify error: {verify_result.error}",
            )

        # Success is determined by verify.sh exit code
        success = verify_result.success

        logger.info(
            f"Verification result for {bounty_id}: {'SUCCESS' if success else 'FAILED'}"
        )

        return VerificationResult(
            bounty_id=bounty_id,
            success=success,
            exploit_output=exploit_result.output,
            verify_output=verify_result.output,
            exploit_exit_code=exploit_result.exit_code,
            verify_exit_code=verify_result.exit_code,
        )

    def verify_all(
        self,
        exploit_scripts: dict[str, str | Path],
        target_host: str | None = None,
    ) -> list[VerificationResult]:
        """Verify multiple bounties.

        Args:
            exploit_scripts: Mapping of bounty_id -> script_path
            target_host: Target host URL (auto-detected if not provided)

        Returns:
            List of VerificationResults
        """
        results = []
        host = target_host or self._get_target_host()

        for bounty_id, script_path in exploit_scripts.items():
            result = self.verify_bounty(bounty_id, script_path, host)
            results.append(result)

        return results

    def verify_exploit_only(
        self,
        exploit_script_path: str | Path,
        target_host: str | None = None,
    ) -> ExploitResult:
        """Run only the exploit without verification.

        Useful for testing exploit scripts independently.

        Args:
            exploit_script_path: Path to the exploit.sh script
            target_host: Target host URL

        Returns:
            ExploitResult with execution details
        """
        host = target_host or self._get_target_host()
        return self._run_exploit(exploit_script_path, host)
