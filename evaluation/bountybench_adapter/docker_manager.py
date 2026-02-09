"""Docker container lifecycle management for BountyBench tasks."""

import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from evaluation.bountybench_adapter.task_loader import TaskLoader

logger = logging.getLogger(__name__)


class DockerManager:
    """Manage Docker container lifecycle for BountyBench tasks.

    Handles starting and stopping Docker containers using docker-compose,
    with support for parallel execution through unique project names.
    """

    def __init__(self, task_loader: "TaskLoader"):
        self.task_loader = task_loader
        self.project_name: str | None = None
        self.compose_file: str | None = None
        self._docker_compose_cmd: list[str] | None = None
        self._service_urls: dict[str, str] = {}
        self._started = False
        self._using_preexisting_containers = False
        self._preexisting_container_names: list[str] = []

    def _detect_docker_compose(self) -> list[str]:
        """Detect docker compose command (v1 vs v2)."""
        if self._docker_compose_cmd is not None:
            return self._docker_compose_cmd

        # Try docker compose (v2)
        try:
            subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                check=True,
            )
            self._docker_compose_cmd = ["docker", "compose"]
            return self._docker_compose_cmd
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        # Try docker-compose (v1)
        if shutil.which("docker-compose"):
            self._docker_compose_cmd = ["docker-compose"]
            return self._docker_compose_cmd

        raise FileNotFoundError("docker compose not found - install Docker")

    def _find_compose_file(self, bounty_id: str | None = None) -> str | None:
        """Find docker-compose file for the task or specific bounty."""
        task_dir = self.task_loader.task_dir

        if bounty_id:
            # Look in bounty's setup_files first
            bounty_dir = task_dir / "bounties" / bounty_id / "setup_files"
            for name in ["docker-compose.yml", "docker-compose.yaml"]:
                candidate = bounty_dir / name
                if candidate.exists():
                    return str(candidate)

        # Look at task level
        for name in ["docker-compose.yml", "docker-compose.yaml"]:
            candidate = task_dir / name
            if candidate.exists():
                return str(candidate)

        return None

    def _ensure_network(self) -> None:
        """Ensure shared_net Docker network exists."""
        try:
            subprocess.run(
                ["docker", "network", "inspect", "shared_net"],
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            logger.info("Creating shared_net Docker network")
            subprocess.run(
                ["docker", "network", "create", "shared_net"],
                capture_output=True,
                check=True,
            )

    def _parse_port_mappings(self, compose_file: str) -> dict[str, str]:
        """Parse docker-compose.yml to extract port mappings.

        Returns dict of service_name -> external URL.

        For services with multiple ports:
        - service_name: maps to first port (backward compat)
        - service_name:port: maps to each specific port

        Example for app with ports 8080 and 3333:
        - "app": "http://localhost:8080"
        - "app:8080": "http://localhost:8080"
        - "app:3333": "http://localhost:3333"
        """
        urls: dict[str, str] = {}

        with open(compose_file) as f:
            compose = yaml.safe_load(f)

        services = compose.get("services", {})
        for service_name, service_config in services.items():
            ports = service_config.get("ports", [])
            first_port_set = False

            for port_mapping in ports:
                host_port: str | None = None

                # Handle "8080:80", "8080:80/tcp", etc.
                if isinstance(port_mapping, str):
                    match = re.match(r"(\d+):(\d+)", port_mapping)
                    if match:
                        host_port = match.group(1)
                elif isinstance(port_mapping, dict):
                    # Handle {"published": 8080, "target": 80} format
                    published = port_mapping.get("published")
                    if published:
                        host_port = str(published)

                if host_port:
                    url = f"http://localhost:{host_port}"
                    # First port becomes the default for the service name
                    if not first_port_set:
                        urls[service_name] = url
                        first_port_set = True
                    # Also add service_name:port for explicit port selection
                    urls[f"{service_name}:{host_port}"] = url

        return urls

    def _check_containers_already_running(self, compose_file: str) -> list[str]:
        """Check if containers from compose file are already running and healthy.

        This handles the case where setup_bounty_env.sh already started the containers.
        Returns list of ALL container names if containers with exposed ports are running
        and healthy, empty list otherwise.
        """
        with open(compose_file) as f:
            compose = yaml.safe_load(f)

        services = compose.get("services", {})
        all_container_names = []
        containers_to_check = []

        for service_name, service_config in services.items():
            # Get container name (explicit or derived from service name)
            container_name = service_config.get("container_name", service_name)
            all_container_names.append(container_name)
            # Only check containers that have exposed ports (externally accessible)
            if service_config.get("ports"):
                containers_to_check.append(container_name)

        if not containers_to_check:
            return []

        # Check if all required containers are running and healthy
        for container_name in containers_to_check:
            try:
                result = subprocess.run(
                    ["docker", "inspect", "--format", "{{.State.Status}} {{.State.Health.Status}}", container_name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode != 0:
                    return []

                output = result.stdout.strip()
                # Container should be running and healthy (or no healthcheck)
                if "running" not in output:
                    return []
                # If there's a healthcheck, it should be healthy
                if "unhealthy" in output:
                    return []

                logger.info(f"Container '{container_name}' already running: {output}")
            except (subprocess.TimeoutExpired, Exception):
                return []

        # Return all container names for cleanup purposes
        return all_container_names

    def _get_env(self) -> dict[str, str]:
        """Get environment with COMPOSE_PROJECT_NAME set."""
        env = os.environ.copy()
        if self.project_name:
            env["COMPOSE_PROJECT_NAME"] = self.project_name
        return env

    def _wait_for_health(self, timeout: int) -> bool:
        """Wait for containers to report healthy status.

        Args:
            timeout: Maximum seconds to wait

        Returns:
            True if all containers are healthy/running, False on timeout
        """
        if not self.compose_file:
            return False

        start = time.time()
        compose_dir = str(Path(self.compose_file).parent)
        env = self._get_env()
        docker_compose = self._detect_docker_compose()

        while time.time() - start < timeout:
            try:
                result = subprocess.run(
                    [
                        *docker_compose,
                        "-f",
                        self.compose_file,
                        "ps",
                        "--format",
                        "json",
                    ],
                    cwd=compose_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0 and result.stdout:
                    output = result.stdout.strip()
                    # Handle both array and line-delimited JSON formats
                    if output.startswith("["):
                        services = json.loads(output)
                    else:
                        # Line-delimited JSON (docker compose v2.21+)
                        services = [
                            json.loads(line)
                            for line in output.split("\n")
                            if line.strip()
                        ]

                    if services:
                        # Check all services are healthy or running (without health checks)
                        all_ready = all(
                            s.get("Health") in ("healthy", "")
                            and s.get("State") == "running"
                            for s in services
                        )
                        if all_ready:
                            logger.info("All containers are healthy/running")
                            return True
            except json.JSONDecodeError as e:
                logger.debug(f"JSON parse error during health check: {e}")
            except subprocess.TimeoutExpired:
                logger.debug("Health check command timed out")
            except Exception as e:
                logger.debug(f"Health check error: {e}")

            time.sleep(3)

        logger.warning(f"Health check timed out after {timeout}s")
        return False

    def run_setup_script(self, bounty_id: str | None = None) -> bool:
        """Execute setup_bounty_env.sh or setup_repo_env.sh if it exists.

        Args:
            bounty_id: If provided, run bounty-specific setup script.
                      Otherwise, run repo-level setup script.

        Returns:
            True if script ran successfully or doesn't exist, False on failure
        """
        if bounty_id:
            setup_script = (
                self.task_loader.task_dir
                / "bounties"
                / bounty_id
                / "setup_files"
                / "setup_bounty_env.sh"
            )
        else:
            setup_script = self.task_loader.task_dir / "setup_repo_env.sh"

        if not setup_script.exists():
            logger.debug(f"No setup script at {setup_script}")
            return True

        logger.info(f"Running setup script: {setup_script}")
        try:
            result = subprocess.run(
                ["bash", str(setup_script)],
                cwd=setup_script.parent,
                capture_output=True,
                text=True,
                timeout=300,  # 5 min timeout for setup scripts
            )
            if result.returncode != 0:
                logger.error(f"Setup script failed (exit {result.returncode})")
                logger.error(f"stderr: {result.stderr}")
                return False
            logger.info("Setup script completed successfully")
            return True
        except subprocess.TimeoutExpired:
            logger.error("Setup script timed out after 300s")
            return False
        except Exception as e:
            logger.error(f"Setup script error: {e}")
            return False

    def start(self, bounty_id: str | None = None, timeout: int = 60) -> dict[str, str]:
        """Start Docker containers for a bounty.

        Args:
            bounty_id: Specific bounty (uses its docker-compose.yml).
                       If None, looks for task-level docker-compose.
            timeout: Seconds to wait for containers to be healthy.

        Returns:
            dict with service info: {service_name: url}
        """
        self.compose_file = self._find_compose_file(bounty_id)
        if not self.compose_file:
            return {}

        # Always force recreate containers to ensure clean state
        # This prevents false positives from verification artifacts left by previous runs
        preexisting_containers = self._check_containers_already_running(self.compose_file)
        if preexisting_containers:
            logger.info("Stopping pre-existing containers to ensure clean state")
            for container_name in preexisting_containers:
                try:
                    subprocess.run(
                        ["docker", "rm", "-f", container_name],
                        capture_output=True,
                        timeout=30,
                    )
                    logger.debug(f"Removed pre-existing container: {container_name}")
                except Exception as e:
                    logger.warning(f"Failed to remove container {container_name}: {e}")

        # Generate unique project name for parallel execution
        task_name = self.task_loader.get_task_name()
        self.project_name = f"{task_name}-{int(time.time())}-{os.getpid()}"

        logger.info(f"Starting Docker containers for {self.project_name}")

        # Ensure shared network exists
        self._ensure_network()

        # Get docker compose command
        docker_compose = self._detect_docker_compose()

        # Set working directory to compose file location
        compose_dir = str(Path(self.compose_file).parent)

        # Start containers
        env = os.environ.copy()
        env["COMPOSE_PROJECT_NAME"] = self.project_name

        try:
            result = subprocess.run(
                [*docker_compose, "-f", self.compose_file, "up", "-d", "--build", "--force-recreate"],
                cwd=compose_dir,
                env=env,
                capture_output=True,
                timeout=timeout + 120,  # Build can take longer
            )
            if result.returncode != 0:
                stderr = result.stderr.decode() if result.stderr else "No stderr"
                stdout = result.stdout.decode() if result.stdout else "No stdout"
                logger.error(f"Docker compose failed (exit {result.returncode})")
                logger.error(f"stderr: {stderr}")
                logger.error(f"stdout: {stdout}")
                raise subprocess.CalledProcessError(
                    result.returncode,
                    result.args,
                    output=result.stdout,
                    stderr=result.stderr,
                )
        except subprocess.TimeoutExpired as e:
            logger.error(f"Docker compose timed out after {timeout + 120}s")
            raise RuntimeError(f"Docker startup timed out: {e}") from e
        except subprocess.CalledProcessError:
            raise

        # Wait for services to be ready using health checks
        logger.info(f"Waiting for services to be ready ({timeout}s)...")
        self._wait_for_health(timeout)

        # Parse service URLs
        self._service_urls = self._parse_port_mappings(self.compose_file)
        self._started = True

        logger.info(f"Services ready: {self._service_urls}")
        return self._service_urls

    def stop(self) -> None:
        """Stop and remove all containers started or used by this manager.

        Handles two cases:
        1. Containers we started ourselves (has project_name) - use docker compose down
        2. Pre-existing containers from setup scripts - use docker rm -f
        """
        if not self.compose_file:
            return

        # Handle pre-existing containers (from setup scripts)
        if self._using_preexisting_containers and self._preexisting_container_names:
            logger.info(f"Stopping pre-existing containers: {self._preexisting_container_names}")
            for container_name in self._preexisting_container_names:
                try:
                    subprocess.run(
                        ["docker", "rm", "-f", container_name],
                        capture_output=True,
                        timeout=30,
                    )
                    logger.debug(f"Removed container: {container_name}")
                except Exception as e:
                    logger.warning(f"Failed to remove container {container_name}: {e}")
            logger.info("Pre-existing containers stopped")
            self._using_preexisting_containers = False
            self._preexisting_container_names = []
            self._started = False
            self._service_urls = {}
            return

        # Handle containers we started ourselves
        if not self.project_name:
            logger.debug("No project name set, skipping Docker cleanup")
            return

        if not self._started:
            logger.warning(
                f"Docker containers may not have fully started for {self.project_name}. "
                "Attempting cleanup anyway."
            )

        logger.info(f"Stopping Docker containers for {self.project_name}")

        try:
            docker_compose = self._detect_docker_compose()
            compose_dir = str(Path(self.compose_file).parent)

            env = os.environ.copy()
            env["COMPOSE_PROJECT_NAME"] = self.project_name

            subprocess.run(
                [*docker_compose, "-f", self.compose_file, "down", "-v"],
                cwd=compose_dir,
                env=env,
                capture_output=True,
                timeout=60,
            )
            logger.info(
                f"Docker containers stopped successfully for {self.project_name}"
            )
        except subprocess.TimeoutExpired:
            logger.error(
                f"Timeout stopping Docker containers for {self.project_name}. "
                "Containers may still be running."
            )
        except FileNotFoundError:
            logger.warning("Docker compose not found during cleanup")
        except Exception as e:
            logger.error(f"Error stopping Docker containers: {e}")
        finally:
            self._started = False
            self._service_urls = {}

    # Well-known database service names (not HTTP-accessible)
    _DB_SERVICES = {"postgres", "postgresql", "mysql", "mariadb", "redis", "mongo", "mongodb", "memcached"}

    def validate_services(self, timeout: int = 10) -> dict[str, dict]:
        """Probe all HTTP services to verify they actually respond.

        Docker health checks only verify that ports are listening. This method
        makes real HTTP requests to catch deeper issues (e.g., database schema
        errors causing 500s on all endpoints).

        Should be called after start() succeeds and before running agents.

        Args:
            timeout: HTTP request timeout per service in seconds

        Returns:
            Dict of service_name -> {"url": str, "status": int|None, "error": str|None, "ok": bool}
        """
        import httpx

        results: dict[str, dict] = {}

        for service_name, url in self._service_urls.items():
            # Skip database services (they don't speak HTTP)
            base_name = service_name.split(":")[0]
            if base_name in self._DB_SERVICES:
                logger.debug(f"Skipping DB service probe: {service_name}")
                continue

            try:
                with httpx.Client(verify=False, timeout=timeout) as client:
                    response = client.get(url)
                    results[service_name] = {
                        "url": url,
                        "status": response.status_code,
                        "error": None,
                        "ok": response.status_code < 500,
                    }
                    if response.status_code >= 500:
                        logger.warning(
                            f"Service {service_name} ({url}) returned {response.status_code} "
                            f"— application may be misconfigured"
                        )
                    else:
                        logger.info(
                            f"Service {service_name} ({url}) responding: {response.status_code}"
                        )
            except Exception as e:
                results[service_name] = {
                    "url": url,
                    "status": None,
                    "error": str(e),
                    "ok": False,
                }
                logger.warning(f"Service {service_name} ({url}) unreachable: {e}")

        # Log summary
        ok_count = sum(1 for r in results.values() if r["ok"])
        total = len(results)
        if total > 0 and ok_count == 0:
            logger.error(
                "ALL HTTP services are failing — agents will likely be unable to "
                "authenticate or interact with the target. Check database migrations "
                "and application configuration."
            )
        elif ok_count < total:
            logger.warning(
                f"{total - ok_count}/{total} HTTP services are failing"
            )

        return results

    def get_service_urls(self) -> dict[str, str]:
        """Get external URLs for all running services."""
        return self._service_urls.copy()

    def is_healthy(self) -> bool:
        """Check if all containers are healthy."""
        if not self._started:
            return False

        try:
            docker_compose = self._detect_docker_compose()
            result = subprocess.run(
                [*docker_compose, "ps", "--format", "json"],
                capture_output=True,
                timeout=10,
            )
            # If command succeeded and containers are running, consider healthy
            return result.returncode == 0
        except Exception:
            return False

    def __enter__(self) -> "DockerManager":
        return self

    def __exit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        self.stop()
