"""
HTTP tools for HTTPAgent.

This module provides HTTP request tools for probing live network services,
plus re-exports code analysis tools for hybrid operation.
"""

from typing import Optional, Dict, Any, Literal

from kai.agents.tools.graph_tools import (
    dependency_graph_resolve,
    dependency_graph_neighbors,
    dependency_graph_paths,
    dependency_graph_loc,
    dependency_graph_slice,
    dependency_graph_callers,
    dependency_graph_callees,
    dependency_graph_snippet,
    dependency_graph_public_entrypoints,
    dependency_graph_protocol_entrypoints,
)
from kai.agents.tools.file_tools import (
    read_file,
    list_files,
)
from kai.agents.tools.shared import get_current_agent


def _get_current_agent():
    """Get the current agent instance from the shared contextvars."""
    return get_current_agent()


# =============================================================================
# HTTP/Network Tools
# =============================================================================

# Maximum response body size to prevent memory issues (10KB)
MAX_RESPONSE_SIZE = 10 * 1024

# Maximum requests per agent run
MAX_REQUESTS_PER_RUN = 50


def http_request(
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    url: str,
    service: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: int = 30,
    follow_redirects: bool = True,
    verify_ssl: bool = False,
) -> Dict[str, Any]:
    """
    Make an HTTP request to a target service.

    Use ${TARGET_HOST} placeholder in URLs - it will be replaced with the
    service's URL at runtime.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
        url: Full URL or path. Use ${TARGET_HOST}/path format.
        service: Service name to target (e.g., "app", "postgres"). Required.
        headers: Optional HTTP headers as a dictionary
        body: Optional raw request body as string
        json_body: Optional JSON body (will be serialized automatically)
        timeout: Request timeout in seconds (default 30)
        follow_redirects: Whether to follow HTTP redirects (default True)
        verify_ssl: Whether to verify SSL certificates (default False for testing)

    Returns:
        Dict with:
            - status_code: HTTP status code
            - headers: Response headers as dict
            - body: Response body (truncated if > 10KB)
            - elapsed_ms: Request duration in milliseconds
            - error: Error message if request failed

    Examples:
        # GET request to app service
        result = http_request("GET", "${TARGET_HOST}/api/users", service="app")

        # POST with JSON body
        result = http_request(
            "POST",
            "${TARGET_HOST}/api/login",
            service="app",
            json_body={"username": "admin", "password": "test"}
        )
    """
    import httpx

    agent = _get_current_agent()

    # Check request limit
    request_count = getattr(agent, "_request_count", 0) if agent else 0
    if request_count >= MAX_REQUESTS_PER_RUN:
        return {
            "status_code": None,
            "headers": {},
            "body": "",
            "truncated": False,
            "elapsed_ms": 0,
            "error": f"Request limit reached ({MAX_REQUESTS_PER_RUN} requests per run)",
        }

    # Resolve target host from service name
    target_hosts = getattr(agent, "target_hosts", {}) if agent else {}
    if not target_hosts:
        return {
            "status_code": None,
            "headers": {},
            "body": "",
            "truncated": False,
            "elapsed_ms": 0,
            "error": "No target_hosts configured. Set http_target_hosts in dispatcher config.",
        }

    # Get the target host for the specified service
    target_host = target_hosts.get(service)
    if not target_host:
        available = ", ".join(target_hosts.keys())
        return {
            "status_code": None,
            "headers": {},
            "body": "",
            "truncated": False,
            "elapsed_ms": 0,
            "error": f"Service '{service}' not found. Available services: {available}",
        }

    # Replace TARGET_HOST placeholder
    url = url.replace("${TARGET_HOST}", target_host)

    try:
        # Build request kwargs
        kwargs: Dict[str, Any] = {
            "method": method,
            "url": url,
            "timeout": timeout,
            "follow_redirects": follow_redirects,
        }

        if headers:
            kwargs["headers"] = headers

        if json_body is not None:
            kwargs["json"] = json_body
        elif body is not None:
            kwargs["content"] = body

        # Make the request
        with httpx.Client(verify=verify_ssl) as client:
            response = client.request(**kwargs)

        # Increment request count
        if agent:
            agent.increment_request_count()

        # Truncate body if too large
        body_text = response.text
        truncated = False
        if len(body_text) > MAX_RESPONSE_SIZE:
            body_text = body_text[:MAX_RESPONSE_SIZE]
            truncated = True

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body_text,
            "truncated": truncated,
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
            "error": None,
        }

    except httpx.TimeoutException:
        return {
            "status_code": None,
            "headers": {},
            "body": "",
            "truncated": False,
            "elapsed_ms": 0,
            "error": f"Request timed out after {timeout} seconds",
        }
    except httpx.RequestError as e:
        return {
            "status_code": None,
            "headers": {},
            "body": "",
            "truncated": False,
            "elapsed_ms": 0,
            "error": f"Request failed: {str(e)}",
        }
    except Exception as e:
        return {
            "status_code": None,
            "headers": {},
            "body": "",
            "truncated": False,
            "elapsed_ms": 0,
            "error": f"Unexpected error: {str(e)}",
        }


def register_http_exploit(
    exploit_found: bool,
    reasoning: str,
    poc_code: str,
    verification_output: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Register an HTTP exploit finding.

    The poc_code MUST be a standalone Python script that:
    1. Uses ${TARGET_HOST} placeholder for the target URL
    2. Uses the `requests` library (NOT httpx) for HTTP calls
    3. Prints output matching verification requirements
    4. Exits with code 0 on success, non-zero on failure

    Args:
        exploit_found: True if you found a vulnerability, False if target is secure
        reasoning: Explanation of your analysis and conclusion
        poc_code: Full Python script that demonstrates the exploit.
                  MUST use ${TARGET_HOST} placeholder.
                  MUST use requests library (not httpx).
        verification_output: Expected output that verify.sh checks for

    Returns:
        Dict with:
            - registered: True if successfully registered
            - exploit_count: Total exploits registered so far
            - message: Status message

    Example poc_code:
        ```python
        import requests
        import sys

        TARGET = "${TARGET_HOST}"

        # Exploit payload
        payload = {"input": "malicious_value"}
        response = requests.post(f"{TARGET}/vulnerable_endpoint", json=payload)

        if "expected_pattern" in response.text:
            print("Exploit successful: vulnerability confirmed")
            sys.exit(0)
        else:
            print("Exploit failed")
            sys.exit(1)
        ```
    """
    agent = _get_current_agent()
    if agent is None:
        return {"registered": False, "error": "No agent context available"}

    # Validate poc_code contains TARGET_HOST placeholder
    if exploit_found and poc_code:
        if "${TARGET_HOST}" not in poc_code:
            return {
                "registered": False,
                "error": "poc_code must contain ${TARGET_HOST} placeholder",
                "message": "Replace hardcoded URLs with ${TARGET_HOST} variable.",
            }

        # Warn if using httpx instead of requests
        if "import httpx" in poc_code or "from httpx" in poc_code:
            return {
                "registered": False,
                "error": "poc_code must use 'requests' library, not 'httpx'",
                "message": "Replace httpx with requests for maximum compatibility.",
            }

    # Initialize exploit registry if not present
    if not hasattr(agent, "_registered_exploits"):
        agent._registered_exploits = []
    if not hasattr(agent, "_exploit_candidates"):
        agent._exploit_candidates = []

    # Determine invariant_id from mission context
    mission = getattr(agent, "mission", None)
    invariant = getattr(mission, "invariant", None) if mission else None
    invariant_id = invariant.id if invariant else "http_exploit"

    # Build exploit record
    exploit_record = {
        "exploit_found": exploit_found,
        "reasoning": reasoning,
        "poc_code": poc_code,
        "verification_output": verification_output,
        "invariant_id": invariant_id,
        "mechanism": "http_exploit",
        "logs": [],
    }
    agent._registered_exploits.append(exploit_record)

    # If exploit found, also add to exploit_candidates for dispatcher
    if exploit_found:
        from kai.schemas import ExploitCandidate

        mission_id = mission.mission_id if mission else "unknown"
        worker_id = getattr(agent, "execution_id", f"agent_{id(agent)}")

        exploit_candidate = ExploitCandidate(
            mission_id=mission_id,
            worker_id=worker_id,
            invariant_id=invariant_id,
            mechanism="http_exploit",
            poc_code=poc_code or "",
            target_file="",
            target_function="",
            description=reasoning,
            compiled=True,  # HTTP exploits don't need compilation
            logs=[f"verification_output: {verification_output}"],
        )
        agent._exploit_candidates.append(exploit_candidate)

    return {
        "registered": True,
        "type": "exploit" if exploit_found else "verification",
        "exploit_count": len(agent._exploit_candidates),
        "finding_count": len(agent._registered_exploits),
        "message": f"Registered {'exploit' if exploit_found else 'verification'}. "
        f"Total exploits: {len(agent._exploit_candidates)}.",
    }


def check_container_file(
    container_name: str,
    file_path: str,
    timeout: int = 10,
) -> Dict[str, Any]:
    """
    Check if a file exists inside a Docker container.

    Use this to verify server-side exploit artifacts. BountyBench's verify.sh
    scripts check for files INSIDE the Docker container, not on the host.

    IMPORTANT: Your exploit should trigger the SERVER to create verification
    files. Do NOT create these files in your PoC code - that creates them on
    the HOST which verify.sh won't see.

    Args:
        container_name: Docker container name (e.g., "internal-app")
        file_path: Path to check inside container (e.g., "/tmp/admin_accessed.txt")
        timeout: Timeout for docker exec command (default 10 seconds)

    Returns:
        Dict with:
            - exists: True if file exists in container
            - content: File contents if exists (truncated to 1KB)
            - error: Error message if command failed

    Examples:
        # Check if server created verification file after exploit
        result = check_container_file("internal-app", "/tmp/admin_accessed.txt")
        if result["exists"]:
            print("Exploit successful: server created verification file")
    """
    import subprocess

    try:
        # First check if file exists
        check_result = subprocess.run(
            ["docker", "exec", container_name, "test", "-f", file_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if check_result.returncode != 0:
            return {
                "exists": False,
                "content": None,
                "error": None,
            }

        # File exists, try to read it
        cat_result = subprocess.run(
            ["docker", "exec", container_name, "cat", file_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        content = cat_result.stdout
        # Truncate if too large
        if len(content) > 1024:
            content = content[:1024] + "\n... (truncated)"

        return {
            "exists": True,
            "content": content,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {
            "exists": False,
            "content": None,
            "error": f"Docker exec timed out after {timeout} seconds",
        }
    except FileNotFoundError:
        return {
            "exists": False,
            "content": None,
            "error": "Docker command not found - is Docker installed?",
        }
    except Exception as e:
        return {
            "exists": False,
            "content": None,
            "error": f"Error checking container file: {str(e)}",
        }


def list_container_processes(
    container_name: str,
    timeout: int = 10,
) -> Dict[str, Any]:
    """
    List running processes inside a Docker container.

    Useful for debugging and understanding what services are running.

    Args:
        container_name: Docker container name
        timeout: Timeout for docker exec command

    Returns:
        Dict with:
            - success: True if command succeeded
            - processes: Process list output
            - error: Error message if failed
    """
    import subprocess

    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "ps", "aux"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode == 0:
            return {
                "success": True,
                "processes": result.stdout,
                "error": None,
            }
        else:
            return {
                "success": False,
                "processes": "",
                "error": result.stderr or "Command failed",
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "processes": "",
            "error": f"Docker exec timed out after {timeout} seconds",
        }
    except Exception as e:
        return {
            "success": False,
            "processes": "",
            "error": str(e),
        }


# =============================================================================
# Code Analysis Tools (re-exported from tools.py at module top)
# =============================================================================
# These allow HTTPAgent to analyze source code alongside HTTP probing
# See imports at top of file

__all__ = [
    # HTTP tools
    "http_request",
    "register_http_exploit",
    # Docker/container tools
    "check_container_file",
    "list_container_processes",
    # Code analysis tools
    "dependency_graph_resolve",
    "dependency_graph_neighbors",
    "dependency_graph_paths",
    "dependency_graph_loc",
    "dependency_graph_slice",
    "dependency_graph_callers",
    "dependency_graph_callees",
    "dependency_graph_snippet",
    "dependency_graph_public_entrypoints",
    "dependency_graph_protocol_entrypoints",
    "read_file",
    "list_files",
]
