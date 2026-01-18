"""
JavaScript tool adapter.

Provides JavaScript/Node.js-specific implementations for:
- Finding Node.js and package managers
- TypeScript compilation or syntax checking
- Running tests with Jest/Mocha/Vitest
- Managing npm/yarn/pnpm dependencies
"""

import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Any, Dict
import json

from kai.utils.tool_adapters.base import (
    ToolAdapter,
    CompileResult,
    InstallResult,
    TestResult,
)


class JavaScriptToolAdapter(ToolAdapter):
    """Tool adapter for JavaScript/Node.js projects."""

    @property
    def framework_name(self) -> str:
        return "javascript"

    @property
    def language(self) -> str:
        return "javascript"

    def find_binary(self, workspace_path: Optional[Path] = None) -> str:
        """
        Find the Node.js binary.

        Returns:
            Path to node binary

        Raises:
            FileNotFoundError: If node is not found
        """
        node_path = shutil.which("node")
        if node_path:
            return node_path

        # Common paths
        common_paths = [
            Path("/usr/local/bin/node"),
            Path("/opt/homebrew/bin/node"),
            Path.home() / ".nvm" / "current" / "bin" / "node",
        ]

        for path in common_paths:
            if path.exists():
                return str(path)

        raise FileNotFoundError("node not found - is Node.js installed?")

    def _detect_package_manager(self, workspace_path: Path) -> str:
        """
        Detect the package manager from lockfiles.

        Returns: "npm", "yarn", or "pnpm"
        """
        if (workspace_path / "pnpm-lock.yaml").exists():
            return "pnpm"
        if (workspace_path / "yarn.lock").exists():
            return "yarn"
        # Default to npm
        return "npm"

    def _get_package_manager_binary(self, manager: str) -> Optional[str]:
        """Get the package manager binary path."""
        return shutil.which(manager)

    def compile(
        self,
        workspace_path: Path,
        timeout: int = 120,
    ) -> CompileResult:
        """
        Check JavaScript/TypeScript syntax.

        For TypeScript projects, runs tsc --noEmit.
        For JavaScript, uses node --check on files.

        Args:
            workspace_path: Path to the workspace directory
            timeout: Timeout in seconds

        Returns:
            CompileResult with success status and parsed errors
        """
        try:
            node_bin = self.find_binary(workspace_path)
        except FileNotFoundError as e:
            return CompileResult(
                success=False,
                errors=[str(e)],
                raw_output="",
            )

        # Check if TypeScript project
        tsconfig = workspace_path / "tsconfig.json"
        if tsconfig.exists():
            # Try to run tsc
            npx_bin = shutil.which("npx")
            if npx_bin:
                try:
                    result = subprocess.run(
                        [npx_bin, "tsc", "--noEmit"],
                        cwd=str(workspace_path),
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )

                    raw_output = result.stdout + result.stderr
                    success = result.returncode == 0

                    errors = []
                    if not success:
                        errors = self.parse_compile_errors(raw_output)

                    return CompileResult(
                        success=success,
                        errors=errors,
                        warnings=[],
                        raw_output=raw_output[:3000]
                        if len(raw_output) > 3000
                        else raw_output,
                    )
                except subprocess.TimeoutExpired:
                    return CompileResult(
                        success=False,
                        errors=[
                            f"TypeScript compilation timed out after {timeout} seconds"
                        ],
                        raw_output="",
                    )
                except Exception as e:
                    return CompileResult(
                        success=False,
                        errors=[f"TypeScript compilation failed: {str(e)}"],
                        raw_output="",
                    )

        # For JavaScript, check syntax with node --check
        js_files = list(workspace_path.rglob("*.js"))
        js_files.extend(workspace_path.rglob("*.mjs"))

        # Skip node_modules and common non-source directories
        skip_dirs = {"node_modules", ".git", "dist", "build", "coverage"}
        js_files = [
            f for f in js_files if not any(skip in f.parts for skip in skip_dirs)
        ]

        if not js_files:
            return CompileResult(
                success=True,
                errors=[],
                raw_output="No JavaScript files found to check",
            )

        errors = []
        all_output = []

        for js_file in js_files[:30]:  # Limit to first 30 files
            try:
                result = subprocess.run(
                    [node_bin, "--check", str(js_file)],
                    cwd=str(workspace_path),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode != 0:
                    error_msg = result.stderr.strip() or result.stdout.strip()
                    errors.append(f"{js_file.name}: {error_msg}")
                    all_output.append(f"=== {js_file} ===\n{error_msg}")

            except subprocess.TimeoutExpired:
                errors.append(f"{js_file.name}: Syntax check timed out")
            except Exception as e:
                errors.append(f"{js_file.name}: {str(e)}")

        raw_output = (
            "\n".join(all_output) if all_output else "All files passed syntax check"
        )

        return CompileResult(
            success=len(errors) == 0,
            errors=errors[:10],
            warnings=[],
            raw_output=raw_output[:3000] if len(raw_output) > 3000 else raw_output,
        )

    def install_dependencies(
        self,
        workspace_path: Path,
        packages: Optional[List[str]] = None,
        timeout: int = 300,
    ) -> InstallResult:
        """
        Install JavaScript dependencies.

        Detects the package manager and installs dependencies.

        Args:
            workspace_path: Path to the workspace directory
            packages: Optional list of specific packages to install
            timeout: Timeout in seconds

        Returns:
            InstallResult with success status and installed packages
        """
        manager = self._detect_package_manager(workspace_path)
        manager_bin = self._get_package_manager_binary(manager)

        if not manager_bin:
            return InstallResult(
                success=False,
                errors=[f"{manager} not found - is it installed?"],
                raw_output="",
            )

        installed: List[str] = []
        errors: List[str] = []
        all_output: List[str] = []

        if packages:
            # Install specific packages
            for package in packages:
                try:
                    if manager == "npm":
                        cmd = [manager_bin, "install", package]
                    elif manager == "yarn":
                        cmd = [manager_bin, "add", package]
                    else:  # pnpm
                        cmd = [manager_bin, "add", package]

                    result = subprocess.run(
                        cmd,
                        cwd=str(workspace_path),
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    output = result.stdout + result.stderr
                    all_output.append(f"=== {package} ===\n{output}")

                    if result.returncode == 0:
                        installed.append(package)
                    else:
                        errors.append(f"{package}: {output[:200]}")
                except subprocess.TimeoutExpired:
                    errors.append(f"{package}: Installation timed out")
                except Exception as e:
                    errors.append(f"{package}: {str(e)}")
        else:
            # Install all dependencies from package.json
            if not (workspace_path / "package.json").exists():
                return InstallResult(
                    success=True,
                    installed=[],
                    raw_output="No package.json found",
                )

            try:
                cmd = [manager_bin, "install"]

                result = subprocess.run(
                    cmd,
                    cwd=str(workspace_path),
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                output = result.stdout + result.stderr
                all_output.append(f"=== {manager} install ===\n{output}")

                if result.returncode == 0:
                    installed.append("package.json")
                else:
                    errors.append(f"{manager} install: {output[:500]}")
            except subprocess.TimeoutExpired:
                errors.append(f"{manager} install: timed out")
            except Exception as e:
                errors.append(f"{manager} install: {str(e)}")

        raw_output = "\n".join(all_output)
        success = len(installed) > 0 or len(errors) == 0

        return InstallResult(
            success=success,
            installed=installed,
            errors=errors,
            raw_output=raw_output[:5000] if len(raw_output) > 5000 else raw_output,
        )

    def _detect_test_framework(self, workspace_path: Path) -> Optional[str]:
        """Detect the test framework from package.json."""
        package_json = workspace_path / "package.json"
        if not package_json.exists():
            return None

        try:
            data = json.loads(package_json.read_text())
            deps = {}
            deps.update(data.get("devDependencies", {}))
            deps.update(data.get("dependencies", {}))

            if "vitest" in deps:
                return "vitest"
            if "jest" in deps:
                return "jest"
            if "mocha" in deps:
                return "mocha"
            if "playwright" in deps:
                return "playwright"
            # Non-standard test frameworks that use their own API (not global describe/it)
            # These run via npm test, not via a CLI runner
            if "tester" in deps:
                return "tester"
            if "tape" in deps:
                return "tape"
            if "ava" in deps:
                return "ava"
            if "node:test" in deps or "@types/node" in deps:
                # Node.js built-in test runner (node:test)
                pass  # Will be detected via test script below

            # Check scripts for test command hints
            scripts = data.get("scripts", {})
            test_script = scripts.get("test", "")
            if "vitest" in test_script:
                return "vitest"
            if "jest" in test_script:
                return "jest"
            if "mocha" in test_script:
                return "mocha"
            # Detect plain node execution (e.g., "node test/index.mjs")
            # These projects use custom test libraries or node:test
            if test_script.startswith("node "):
                return "node-script"

        except Exception:
            pass

        return None

    def _discover_poc_file(self, workspace_path: Path) -> Optional[str]:
        """
        Auto-discover PoC files in standard locations.

        When using non-standard test frameworks that don't pick up files
        from tests/poc/, this method finds PoC files to run directly with node.

        Args:
            workspace_path: Path to the workspace directory

        Returns:
            Relative path to the first PoC file found, or None
        """
        poc_dirs = ["tests/poc", "test/poc", "__tests__/poc"]
        # Prefer .mjs files (ES modules work directly with node)
        poc_extensions = [".mjs", ".js"]

        for poc_dir in poc_dirs:
            dir_path = workspace_path / poc_dir
            if dir_path.exists() and dir_path.is_dir():
                for ext in poc_extensions:
                    # Sort to get consistent results
                    poc_files = sorted(dir_path.glob(f"*{ext}"))
                    for poc_file in poc_files:
                        # Skip files that look like config or setup files
                        if poc_file.name.startswith("_") or poc_file.name.startswith("."):
                            continue
                        # Return the relative path
                        return str(poc_file.relative_to(workspace_path))
        return None

    def _build_poc_command(
        self,
        workspace_path: Path,
        framework_kwargs: Optional[Dict[str, Any]] = None,
    ) -> Optional[List[str]]:
        """
        Build command to run PoC file directly with node.

        For non-standard test frameworks (tester, tape, ava, node-script) or
        unknown frameworks, we run PoC files directly with node instead of
        using a test runner CLI.

        Args:
            workspace_path: Path to the workspace directory
            framework_kwargs: Optional dict with "match_path" key

        Returns:
            Command list [node_bin, test_file] or None if no PoC found
        """
        fw = framework_kwargs or {}
        match_path = fw.get("match_path") or self._discover_poc_file(workspace_path)

        if not match_path:
            return None

        test_file = workspace_path / match_path
        if not test_file.exists():
            return None

        try:
            node_bin = self.find_binary(workspace_path)
            return [node_bin, str(test_file)]
        except FileNotFoundError:
            return None

    def run_test(
        self,
        workspace_path: Path,
        match_contract: Optional[str] = None,
        match_test: Optional[str] = None,
        verbosity: int = 2,
        timeout: int = 300,
        additional_args: Optional[str] = None,
        framework_kwargs: Optional[Dict[str, Any]] = None,
    ) -> TestResult:
        """
        Run JavaScript tests using detected framework.

        Args:
            workspace_path: Path to the workspace directory
            match_contract: Filter by file pattern
            match_test: Filter by test name pattern
            verbosity: Verbosity level
            timeout: Timeout in seconds
            additional_args: Additional test arguments
            framework_kwargs: Framework-specific options

        Returns:
            TestResult with parsed test outcomes
        """
        manager = self._detect_package_manager(workspace_path)
        npx_bin = shutil.which("npx")

        if not npx_bin:
            return TestResult(success=False, error="npx not found")

        test_framework = self._detect_test_framework(workspace_path)

        # Build command based on test framework
        if test_framework == "vitest":
            cmd = [npx_bin, "vitest", "run"]
            if match_test:
                cmd.extend(["-t", match_test])
            if match_contract:
                cmd.append(match_contract)
        elif test_framework == "jest":
            cmd = [npx_bin, "jest"]
            if match_test:
                cmd.extend(["-t", match_test])
            if match_contract:
                cmd.append(match_contract)
        elif test_framework == "mocha":
            cmd = [npx_bin, "mocha"]
            if match_test:
                cmd.extend(["--grep", match_test])
            if match_contract:
                cmd.append(match_contract)
        else:
            # Non-standard frameworks (tester, tape, ava, node-script) or unknown
            # These don't provide global describe/it/expect, so we run PoC files
            # directly with node. Files must use node:assert for assertions.
            cmd = self._build_poc_command(workspace_path, framework_kwargs)
            if cmd is None:
                # No PoC file found, fall back to npm test
                manager_bin = self._get_package_manager_binary(manager)
                if not manager_bin:
                    return TestResult(success=False, error=f"{manager} not found")
                cmd = [manager_bin, "test"]

        # Add verbosity (framework-specific)
        if test_framework == "jest" and verbosity > 1:
            cmd.append("--verbose")

        # Additional args
        if additional_args:
            import shlex

            cmd.extend(shlex.split(additional_args))

        # Framework-specific kwargs
        fw = framework_kwargs or {}
        if fw.get("coverage"):
            if test_framework in ("jest", "vitest"):
                cmd.append("--coverage")

        try:
            result = subprocess.run(
                cmd,
                cwd=str(workspace_path),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = result.stdout + result.stderr
            success = result.returncode == 0

            # Parse test output
            parsed = self._parse_test_output(output, test_framework)

            return TestResult(
                success=success,
                tests_passed=parsed["tests_passed"],
                tests_failed=parsed["tests_failed"],
                assertion_failures=parsed["assertion_failures"],
                reverts=parsed["reverts"],
                parsed_results=parsed["parsed_results"],
                raw_output=output[:5000] if len(output) > 5000 else output,
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                success=False,
                error=f"Test execution timed out after {timeout} seconds",
                raw_output=f"Test execution timed out after {timeout} seconds",
            )
        except Exception as e:
            return TestResult(success=False, error=str(e))

    def get_test_file_extension(self) -> str:
        """Return JavaScript test file extension."""
        return ".test.js"

    def get_source_file_extension(self) -> str:
        """Return JavaScript source file extension."""
        return ".js"

    def normalize_test_path(self, file_path: str, workspace: Path) -> Path:
        """Normalize test path for JavaScript projects."""
        p = Path(file_path)

        if p.is_absolute():
            p = Path(p.name)

        normalized = p.as_posix().lstrip("/")

        # Strip leading test directories
        for prefix in ["tests/", "test/", "__tests__/"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
                break

        # Valid test file extensions (don't modify these)
        valid_extensions = [
            ".test.js", ".test.ts", ".test.mjs", ".test.mts",
            ".spec.js", ".spec.ts", ".spec.mjs", ".spec.mts",
            ".mjs", ".mts",  # ES modules can be run directly with node
        ]

        # Ensure proper extension
        # Prefer .mjs for framework-agnostic PoC files that can run directly with node
        if not any(normalized.endswith(ext) for ext in valid_extensions):
            if normalized.endswith(".js"):
                normalized = normalized[:-3] + ".mjs"
            elif normalized.endswith(".ts"):
                normalized = normalized[:-3] + ".test.ts"
            else:
                normalized = normalized + ".mjs"

        return workspace / "tests" / "poc" / normalized

    def get_allowed_patch_directories(self) -> List[str]:
        """Return allowed directories for patching."""
        return ["tests/poc", "__tests__/poc", "test/poc", "tests/exploits"]

    def parse_compile_errors(self, output: str) -> List[str]:
        """Parse TypeScript/JavaScript compilation errors."""
        errors = []
        for line in output.split("\n"):
            line_stripped = line.strip()
            line_lower = line_stripped.lower()

            if "error" in line_lower and ("ts" in line_lower or ":" in line_stripped):
                errors.append(line_stripped)
            elif line_stripped.startswith("error"):
                errors.append(line_stripped)

        # Deduplicate
        seen = set()
        unique_errors = []
        for e in errors:
            if e not in seen:
                seen.add(e)
                unique_errors.append(e)

        return unique_errors[:10]

    def get_tool_description(self, tool_name: str) -> Optional[str]:
        """Get JavaScript-specific tool descriptions."""
        descriptions = {
            "write_and_compile": """Write a JavaScript test file to the workspace and check syntax.

IMPORTANT: Use framework-agnostic code. Do NOT use Mocha/Jest/Chai globals.

Args:
    file_path: Test file name with .mjs extension (e.g., "poc/exploit.mjs")
    content: JavaScript test file content using node:assert

Returns:
    {"written": bool, "path": str, "compiled": bool, "errors": List[str], "raw_output": str}

Example:
    result = write_and_compile("poc/exploit.mjs", '''
import assert from "assert";
import targetModule from "package-name";  // Use package name, not relative path

// Test directly - NO describe/it blocks
const result = targetModule.vulnerableMethod(maliciousInput);

// Use node:assert for assertions
assert.strictEqual(result.exploited, true, "Vulnerability demonstrated");

console.log("PoC PASSED: vulnerability confirmed");
process.exit(0);
    ''')

    if not result["compiled"]:
        # Fix errors in result["errors"]
        pass""",
            "run_test": """Run JavaScript tests (runs PoC files directly with node).

Args:
    match_contract: Filter by file pattern
    match_test: Filter by test name pattern
    verbosity: Verbosity level
    additional_args: Extra test arguments
    framework_kwargs: Optional dict with "match_path" to specify PoC file

Returns:
    {
        "success": bool,
        "tests_passed": int,
        "tests_failed": int,
        "assertion_failures": List[str],
        "parsed_results": Dict[str, str],
        "raw_output": str
    }

Example:
    result = run_test()  # Auto-discovers PoC in tests/poc/

    if result["success"]:
        print("PoC passed - vulnerability confirmed!")""",
            "register_exploit": """Register an exploit finding for JavaScript.

Args:
    exploit_found: True if you found a way to exploit the vulnerability
    reasoning: Explanation of your analysis and conclusion
    poc_path: Path to the PoC test file (e.g., "tests/poc/exploit.mjs")
    poc_code: Full JavaScript code of the PoC (framework-agnostic)

Example:
    register_exploit(
        exploit_found=True,
        reasoning="The prototype pollution in merge() allows arbitrary property injection...",
        poc_path="tests/poc/prototype_pollution.mjs",
        poc_code='''
import assert from "assert";
import { merge } from "package-name";

// Test prototype pollution - NO describe/it blocks
const target = {};
const payload = JSON.parse('{"__proto__": {"admin": true}}');
merge(target, payload);

assert.strictEqual({}.admin, true, "Prototype polluted");
console.log("PoC PASSED: prototype pollution confirmed");
process.exit(0);
'''
    )""",
        }
        return descriptions.get(tool_name)

    def get_poc_guidance(self) -> str:
        """Get JavaScript-specific PoC writing guidance."""
        return """## PoC Format: JavaScript/Node.js
Write JavaScript test files in tests/poc/ with .mjs extension (ES modules).

**CRITICAL: Use framework-agnostic code. Do NOT use:**
- describe(), it(), test() - These are Mocha/Jest globals that won't work
- expect(), chai - These require installation
- jest.mock(), vi.mock() - These are framework-specific

**Correct PoC structure:**
```javascript
import assert from 'assert';

// IMPORT RULES:
// 1. PREFERRED: Import from package name (works if installed)
import targetModule from 'package-name';
// 2. FALLBACK: Import from dist/ (compiled output)
// import targetModule from '../dist/index.js';
// 3. WRONG: Do NOT import from src/ (source code, may not work)
// import targetModule from '../src/index.js';  // WRONG!

// Test directly - NO describe/it blocks
const result = targetModule(maliciousInput);

// Use node:assert for assertions
assert.strictEqual(result.property, expected, 'Exploit demonstrated');

console.log('PoC PASSED: vulnerability confirmed');
process.exit(0);  // Exit 0 = success
```

**Import path rules:**
1. Check package.json "main" or "exports" field for the correct entry point
2. Prefer package name: `import x from 'package-name'`
3. If relative path needed, use dist/: `import x from '../dist/index.js'`
4. Include .js extension in relative imports (required for ES modules)
5. NEVER import from src/ directly - it may contain uncompiled TypeScript

**Key rules:**
- Use .mjs extension for ES module support
- Use `import assert from 'assert'` for assertions
- Exit with code 0 = exploit succeeded, non-zero = failed
- Print clear output showing what was exploited"""

    def _parse_test_output(self, output: str, framework: Optional[str]) -> dict:
        """Parse test framework output to extract results."""
        tests_passed = 0
        tests_failed = 0
        assertion_failures: List[str] = []
        reverts: List[str] = []
        parsed_results: dict = {}

        import re

        # Jest format: "Tests: X passed, Y failed"
        jest_match = re.search(
            r"Tests:\s*(\d+)\s*passed.*?(\d+)\s*failed", output, re.IGNORECASE
        )
        if jest_match:
            tests_passed = int(jest_match.group(1))
            tests_failed = int(jest_match.group(2))

        # Also check for single passed/failed counts
        if not jest_match:
            passed_match = re.search(
                r"(\d+)\s*(?:tests?\s*)?pass(?:ed|ing)?", output, re.IGNORECASE
            )
            failed_match = re.search(
                r"(\d+)\s*(?:tests?\s*)?fail(?:ed|ing)?", output, re.IGNORECASE
            )
            if passed_match:
                tests_passed = int(passed_match.group(1))
            if failed_match:
                tests_failed = int(failed_match.group(1))

        # Check for assertion errors
        if "AssertionError" in output or "Expected" in output:
            assertion_failures.append("assertion_error")

        # Parse individual test results from output
        for line in output.split("\n"):
            if "✓" in line or "PASS" in line:
                test_name = line.strip()
                parsed_results[test_name] = "pass"
            elif "✗" in line or "FAIL" in line:
                test_name = line.strip()
                parsed_results[test_name] = "fail"

        return {
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "assertion_failures": assertion_failures,
            "reverts": reverts,
            "parsed_results": parsed_results,
        }
