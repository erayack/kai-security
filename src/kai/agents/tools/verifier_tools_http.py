"""
HTTP-enabled tools for VerifierAgent - validating HTTP exploit findings.

This module extends the standard verifier tools with HTTP capabilities:
- HTTP request tools for testing exploits against live services
- Container inspection tools for checking server-side artifacts
- Standard verifier tools (graph, test execution, verdict)

Only loaded when --enable-http-agent flag is set.
"""

import sys
from typing import Dict, Any

# Import standard verifier tools
from kai.agents.tools.verifier_tools import (
    dependency_graph_resolve,
    dependency_graph_snippet,
    dependency_graph_neighbors,
    write_and_compile,
    run_test,
    submit_verdict,
)

# Import HTTP tools for verifying HTTP exploits
from kai.agents.tools.http_tools import (
    http_request,
    socket_connect,
    analyze_response,
    check_container_file,
    list_container_processes,
)

# Import shared tools
from kai.agents.tools.shared import get_current_agent as _get_current_agent


def execute_http_poc(
    poc_code: str,
    service: str,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
        Execute an HTTP PoC script and capture output.

        Runs a Python script that makes HTTP requests. The script should use
        ${TARGET_HOST} placeholder which will be replaced with the service's URL.

        Args:
            poc_code: Python code to execute (should use ${TARGET_HOST} placeholder)
            service: Service name to target (e.g., "app", "postgres"). Required.
            timeout: Execution timeout in seconds (default 30)

        Returns:
            Dict with:
                - success: True if script exited with code 0
                - exit_code: Script exit code
                - stdout: Standard output
                - stderr: Standard error
                - error: Error message if execution failed

        Example:
            result = execute_http_poc('''
    import requests
    import sys

    TARGET = "${TARGET_HOST}"
    response = requests.get(f"{TARGET}/api/test")
    if "vulnerable" in response.text:
        print("Exploit successful")
        sys.exit(0)
    else:
        print("Exploit failed")
        sys.exit(1)
    ''', service="app")
            if result["success"]:
                print("PoC executed successfully")
    """
    import subprocess
    import tempfile
    from pathlib import Path

    agent = _get_current_agent()

    # Get target_hosts from agent
    target_hosts = getattr(agent, "target_hosts", {}) if agent else {}

    if not target_hosts:
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": "No target_hosts configured. Set http_target_hosts in dispatcher config.",
        }

    # Resolve target host from service name
    target_host = target_hosts.get(service)
    if not target_host:
        available = ", ".join(target_hosts.keys())
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": f"Service '{service}' not found. Available services: {available}",
        }

    # Substitute TARGET_HOST placeholder
    substituted_code = poc_code.replace("${TARGET_HOST}", target_host)

    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(substituted_code)
        script_path = Path(f.name)

    try:
        # Execute the script with the same Python interpreter
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return {
            "success": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout": result.stdout[:10000] if result.stdout else "",  # Truncate
            "stderr": result.stderr[:10000] if result.stderr else "",  # Truncate
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": f"PoC execution timed out after {timeout} seconds",
        }
    except Exception as e:
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": f"PoC execution failed: {str(e)}",
        }
    finally:
        # Cleanup
        script_path.unlink(missing_ok=True)


__all__ = [
    # Standard verifier tools
    "dependency_graph_resolve",
    "dependency_graph_snippet",
    "dependency_graph_neighbors",
    "write_and_compile",
    "run_test",
    "submit_verdict",
    # HTTP tools for verifying HTTP exploits
    "http_request",
    "socket_connect",
    "analyze_response",
    "check_container_file",
    "list_container_processes",
    # HTTP PoC execution
    "execute_http_poc",
]
