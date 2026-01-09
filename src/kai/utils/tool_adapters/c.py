"""
C tool adapter.

Provides C-specific implementations for:
- Finding gcc/clang or cmake
- Detecting and using build systems (CMake, Make, Meson, Autoconf)
- Running tests with ctest or make test
- Compiling C code
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Any, Dict

from kai.utils.tool_adapters.base import (
    ToolAdapter,
    CompileResult,
    InstallResult,
    TestResult,
)


class CToolAdapter(ToolAdapter):
    """Tool adapter for C projects."""

    @property
    def framework_name(self) -> str:
        return "c"

    @property
    def language(self) -> str:
        return "c"

    def find_binary(self, workspace_path: Optional[Path] = None) -> str:
        """
        Find the C compiler (gcc or clang) or cmake.

        Returns:
            Path to compiler/build tool binary

        Raises:
            FileNotFoundError: If no suitable tool is found
        """
        # First check for cmake
        cmake_path = shutil.which("cmake")
        if cmake_path:
            return cmake_path

        # Check for compilers
        for compiler in ["gcc", "clang", "cc"]:
            compiler_path = shutil.which(compiler)
            if compiler_path:
                return compiler_path

        raise FileNotFoundError(
            "C compiler not found - install gcc, clang, or cmake"
        )

    def _detect_build_system(self, workspace_path: Path) -> str:
        """
        Detect the build system used in the project.

        Returns: "cmake", "make", "autoconf", "meson", or "direct"
        """
        if (workspace_path / "CMakeLists.txt").exists():
            return "cmake"
        if (workspace_path / "Makefile").exists():
            return "make"
        if (workspace_path / "configure").exists() or (workspace_path / "configure.ac").exists():
            return "autoconf"
        if (workspace_path / "meson.build").exists():
            return "meson"
        return "direct"

    def compile(
        self,
        workspace_path: Path,
        timeout: int = 120,
    ) -> CompileResult:
        """
        Compile the C project using detected build system.

        Args:
            workspace_path: Path to the workspace directory
            timeout: Timeout in seconds

        Returns:
            CompileResult with success status and parsed errors
        """
        build_system = self._detect_build_system(workspace_path)

        try:
            if build_system == "cmake":
                return self._compile_cmake(workspace_path, timeout)
            elif build_system == "make":
                return self._compile_make(workspace_path, timeout)
            elif build_system == "meson":
                return self._compile_meson(workspace_path, timeout)
            elif build_system == "autoconf":
                return self._compile_autoconf(workspace_path, timeout)
            else:
                return self._compile_direct(workspace_path, timeout)
        except Exception as e:
            return CompileResult(
                success=False,
                errors=[str(e)],
                raw_output="",
            )

    def _compile_cmake(self, workspace_path: Path, timeout: int) -> CompileResult:
        """Compile using CMake."""
        cmake_bin = shutil.which("cmake")
        if not cmake_bin:
            return CompileResult(
                success=False,
                errors=["cmake not found"],
                raw_output="",
            )

        build_dir = workspace_path / "build"
        build_dir.mkdir(exist_ok=True)

        all_output = []

        # Configure
        try:
            result = subprocess.run(
                [cmake_bin, ".."],
                cwd=str(build_dir),
                capture_output=True,
                text=True,
                timeout=timeout // 2,
            )
            all_output.append(f"=== cmake configure ===\n{result.stdout}{result.stderr}")

            if result.returncode != 0:
                return CompileResult(
                    success=False,
                    errors=self.parse_compile_errors(result.stderr),
                    raw_output="\n".join(all_output),
                )
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                errors=["cmake configure timed out"],
                raw_output="",
            )

        # Build
        try:
            result = subprocess.run(
                [cmake_bin, "--build", "."],
                cwd=str(build_dir),
                capture_output=True,
                text=True,
                timeout=timeout // 2,
            )
            all_output.append(f"=== cmake build ===\n{result.stdout}{result.stderr}")

            raw_output = "\n".join(all_output)
            return CompileResult(
                success=result.returncode == 0,
                errors=self.parse_compile_errors(result.stderr) if result.returncode != 0 else [],
                warnings=self.parse_compile_warnings(result.stdout + result.stderr),
                raw_output=raw_output[:3000] if len(raw_output) > 3000 else raw_output,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                errors=["cmake build timed out"],
                raw_output="\n".join(all_output),
            )

    def _compile_make(self, workspace_path: Path, timeout: int) -> CompileResult:
        """Compile using Make."""
        make_bin = shutil.which("make")
        if not make_bin:
            return CompileResult(
                success=False,
                errors=["make not found"],
                raw_output="",
            )

        try:
            result = subprocess.run(
                [make_bin],
                cwd=str(workspace_path),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            raw_output = result.stdout + result.stderr
            return CompileResult(
                success=result.returncode == 0,
                errors=self.parse_compile_errors(raw_output) if result.returncode != 0 else [],
                warnings=self.parse_compile_warnings(raw_output),
                raw_output=raw_output[:3000] if len(raw_output) > 3000 else raw_output,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                errors=["make timed out"],
                raw_output="",
            )

    def _compile_meson(self, workspace_path: Path, timeout: int) -> CompileResult:
        """Compile using Meson."""
        meson_bin = shutil.which("meson")
        ninja_bin = shutil.which("ninja")

        if not meson_bin:
            return CompileResult(
                success=False,
                errors=["meson not found"],
                raw_output="",
            )

        build_dir = workspace_path / "build"
        all_output = []

        # Setup if needed
        if not build_dir.exists():
            try:
                result = subprocess.run(
                    [meson_bin, "setup", "build"],
                    cwd=str(workspace_path),
                    capture_output=True,
                    text=True,
                    timeout=timeout // 2,
                )
                all_output.append(f"=== meson setup ===\n{result.stdout}{result.stderr}")

                if result.returncode != 0:
                    return CompileResult(
                        success=False,
                        errors=self.parse_compile_errors(result.stderr),
                        raw_output="\n".join(all_output),
                    )
            except subprocess.TimeoutExpired:
                return CompileResult(
                    success=False,
                    errors=["meson setup timed out"],
                    raw_output="",
                )

        # Compile
        compile_cmd = [ninja_bin] if ninja_bin else [meson_bin, "compile", "-C", "build"]
        try:
            result = subprocess.run(
                compile_cmd,
                cwd=str(build_dir) if ninja_bin else str(workspace_path),
                capture_output=True,
                text=True,
                timeout=timeout // 2,
            )
            all_output.append(f"=== meson compile ===\n{result.stdout}{result.stderr}")

            raw_output = "\n".join(all_output)
            return CompileResult(
                success=result.returncode == 0,
                errors=self.parse_compile_errors(result.stderr) if result.returncode != 0 else [],
                warnings=self.parse_compile_warnings(result.stdout + result.stderr),
                raw_output=raw_output[:3000] if len(raw_output) > 3000 else raw_output,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                errors=["meson compile timed out"],
                raw_output="\n".join(all_output),
            )

    def _compile_autoconf(self, workspace_path: Path, timeout: int) -> CompileResult:
        """Compile using autoconf (./configure && make)."""
        all_output = []

        # Run configure if exists
        configure = workspace_path / "configure"
        if configure.exists():
            try:
                result = subprocess.run(
                    ["./configure"],
                    cwd=str(workspace_path),
                    capture_output=True,
                    text=True,
                    timeout=timeout // 2,
                )
                all_output.append(f"=== configure ===\n{result.stdout}{result.stderr}")

                if result.returncode != 0:
                    return CompileResult(
                        success=False,
                        errors=[f"configure failed: {result.stderr[:500]}"],
                        raw_output="\n".join(all_output),
                    )
            except subprocess.TimeoutExpired:
                return CompileResult(
                    success=False,
                    errors=["configure timed out"],
                    raw_output="",
                )

        # Then make
        return self._compile_make(workspace_path, timeout // 2)

    def _compile_direct(self, workspace_path: Path, timeout: int) -> CompileResult:
        """Compile C files directly with gcc/clang."""
        try:
            compiler = self.find_binary()
        except FileNotFoundError as e:
            return CompileResult(
                success=False,
                errors=[str(e)],
                raw_output="",
            )

        # Find all .c files
        c_files = list(workspace_path.rglob("*.c"))
        skip_dirs = {"build", ".git", "test", "tests"}
        c_files = [f for f in c_files if not any(skip in f.parts for skip in skip_dirs)]

        if not c_files:
            return CompileResult(
                success=True,
                errors=[],
                raw_output="No C files found to compile",
            )

        # Try to compile each file (syntax check only)
        errors = []
        all_output = []

        for c_file in c_files[:20]:  # Limit
            try:
                result = subprocess.run(
                    [compiler, "-fsyntax-only", str(c_file)],
                    cwd=str(workspace_path),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode != 0:
                    error_msg = result.stderr.strip()
                    errors.append(f"{c_file.name}: {error_msg[:200]}")
                    all_output.append(f"=== {c_file} ===\n{error_msg}")

            except Exception as e:
                errors.append(f"{c_file.name}: {str(e)}")

        raw_output = "\n".join(all_output) if all_output else "All files passed syntax check"

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
        Install C dependencies (git submodules, CMake FetchContent).

        Args:
            workspace_path: Path to the workspace directory
            packages: Optional list of packages (git URLs)
            timeout: Timeout in seconds

        Returns:
            InstallResult with success status
        """
        installed: List[str] = []
        errors: List[str] = []
        all_output: List[str] = []

        # Initialize git submodules if present
        gitmodules = workspace_path / ".gitmodules"
        if gitmodules.exists():
            git_bin = shutil.which("git")
            if git_bin:
                try:
                    result = subprocess.run(
                        [git_bin, "submodule", "update", "--init", "--recursive"],
                        cwd=str(workspace_path),
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    output = result.stdout + result.stderr
                    all_output.append(f"=== git submodules ===\n{output}")

                    if result.returncode == 0:
                        installed.append("git-submodules")
                    else:
                        errors.append(f"git submodules: {output[:200]}")
                except subprocess.TimeoutExpired:
                    errors.append("git submodules: timed out")
                except Exception as e:
                    errors.append(f"git submodules: {str(e)}")

        # For specific packages (git URLs), clone them
        if packages:
            git_bin = shutil.which("git")
            if git_bin:
                deps_dir = workspace_path / "deps"
                deps_dir.mkdir(exist_ok=True)

                for package in packages:
                    try:
                        # Extract repo name from URL
                        repo_name = package.rstrip("/").split("/")[-1].replace(".git", "")
                        target_dir = deps_dir / repo_name

                        if target_dir.exists():
                            installed.append(package)
                            continue

                        result = subprocess.run(
                            [git_bin, "clone", "--depth", "1", package, str(target_dir)],
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
                        errors.append(f"{package}: clone timed out")
                    except Exception as e:
                        errors.append(f"{package}: {str(e)}")

        raw_output = "\n".join(all_output) if all_output else "No dependencies to install"
        success = len(installed) > 0 or len(errors) == 0

        return InstallResult(
            success=success,
            installed=installed,
            errors=errors,
            raw_output=raw_output[:5000] if len(raw_output) > 5000 else raw_output,
        )

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
        Run C tests using detected method.

        Args:
            workspace_path: Path to the workspace directory
            match_contract: Filter by test file/executable
            match_test: Filter by test name (if supported)
            verbosity: Verbosity level
            timeout: Timeout in seconds
            additional_args: Additional test arguments
            framework_kwargs: Framework-specific options

        Returns:
            TestResult with parsed test outcomes
        """
        build_system = self._detect_build_system(workspace_path)

        if build_system == "cmake":
            return self._run_ctest(workspace_path, match_test, timeout)
        elif build_system == "make":
            return self._run_make_test(workspace_path, timeout)
        elif build_system == "meson":
            return self._run_meson_test(workspace_path, timeout)
        else:
            return self._run_direct_test(workspace_path, match_contract, timeout)

    def _run_ctest(self, workspace_path: Path, match_test: Optional[str], timeout: int) -> TestResult:
        """Run tests using ctest."""
        ctest_bin = shutil.which("ctest")
        if not ctest_bin:
            return TestResult(success=False, error="ctest not found")

        build_dir = workspace_path / "build"
        if not build_dir.exists():
            return TestResult(success=False, error="build directory not found - run compile first")

        cmd = [ctest_bin, "--output-on-failure"]
        if match_test:
            cmd.extend(["-R", match_test])

        try:
            result = subprocess.run(
                cmd,
                cwd=str(build_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = result.stdout + result.stderr
            parsed = self._parse_ctest_output(output)

            return TestResult(
                success=result.returncode == 0,
                tests_passed=parsed["tests_passed"],
                tests_failed=parsed["tests_failed"],
                assertion_failures=parsed["assertion_failures"],
                reverts=[],
                parsed_results=parsed["parsed_results"],
                raw_output=output[:5000] if len(output) > 5000 else output,
            )
        except subprocess.TimeoutExpired:
            return TestResult(
                success=False,
                error=f"ctest timed out after {timeout} seconds",
                raw_output="",
            )
        except Exception as e:
            return TestResult(success=False, error=str(e))

    def _run_make_test(self, workspace_path: Path, timeout: int) -> TestResult:
        """Run tests using make test."""
        make_bin = shutil.which("make")
        if not make_bin:
            return TestResult(success=False, error="make not found")

        try:
            result = subprocess.run(
                [make_bin, "test"],
                cwd=str(workspace_path),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = result.stdout + result.stderr

            return TestResult(
                success=result.returncode == 0,
                tests_passed=1 if result.returncode == 0 else 0,
                tests_failed=0 if result.returncode == 0 else 1,
                raw_output=output[:5000] if len(output) > 5000 else output,
            )
        except subprocess.TimeoutExpired:
            return TestResult(
                success=False,
                error=f"make test timed out after {timeout} seconds",
                raw_output="",
            )
        except Exception as e:
            return TestResult(success=False, error=str(e))

    def _run_meson_test(self, workspace_path: Path, timeout: int) -> TestResult:
        """Run tests using meson test."""
        meson_bin = shutil.which("meson")
        if not meson_bin:
            return TestResult(success=False, error="meson not found")

        try:
            result = subprocess.run(
                [meson_bin, "test", "-C", "build"],
                cwd=str(workspace_path),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = result.stdout + result.stderr

            return TestResult(
                success=result.returncode == 0,
                tests_passed=1 if result.returncode == 0 else 0,
                tests_failed=0 if result.returncode == 0 else 1,
                raw_output=output[:5000] if len(output) > 5000 else output,
            )
        except subprocess.TimeoutExpired:
            return TestResult(
                success=False,
                error=f"meson test timed out after {timeout} seconds",
                raw_output="",
            )
        except Exception as e:
            return TestResult(success=False, error=str(e))

    def _run_direct_test(self, workspace_path: Path, test_executable: Optional[str], timeout: int) -> TestResult:
        """Run test executables directly."""
        # Find test executables
        test_paths = []

        if test_executable:
            test_path = workspace_path / test_executable
            if test_path.exists():
                test_paths.append(test_path)
        else:
            # Look for common test executable patterns
            for pattern in ["test_*", "*_test", "tests/*"]:
                for path in workspace_path.glob(pattern):
                    if path.is_file() and os.access(path, os.X_OK):
                        test_paths.append(path)

            # Check build directory
            build_dir = workspace_path / "build"
            if build_dir.exists():
                for pattern in ["test_*", "*_test"]:
                    for path in build_dir.glob(pattern):
                        if path.is_file() and os.access(path, os.X_OK):
                            test_paths.append(path)

        if not test_paths:
            return TestResult(
                success=False,
                error="No test executables found",
                raw_output="",
            )

        tests_passed = 0
        tests_failed = 0
        all_output = []
        parsed_results = {}

        for test_path in test_paths[:10]:  # Limit
            try:
                result = subprocess.run(
                    [str(test_path)],
                    cwd=str(workspace_path),
                    capture_output=True,
                    text=True,
                    timeout=timeout // max(len(test_paths), 1),
                )

                output = result.stdout + result.stderr
                all_output.append(f"=== {test_path.name} ===\n{output}")

                if result.returncode == 0:
                    tests_passed += 1
                    parsed_results[test_path.name] = "pass"
                else:
                    tests_failed += 1
                    parsed_results[test_path.name] = "fail"

            except subprocess.TimeoutExpired:
                tests_failed += 1
                parsed_results[test_path.name] = "timeout"
                all_output.append(f"=== {test_path.name} ===\nTIMEOUT")
            except Exception as e:
                tests_failed += 1
                parsed_results[test_path.name] = "error"
                all_output.append(f"=== {test_path.name} ===\nERROR: {str(e)}")

        raw_output = "\n".join(all_output)

        return TestResult(
            success=tests_failed == 0 and tests_passed > 0,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            parsed_results=parsed_results,
            raw_output=raw_output[:5000] if len(raw_output) > 5000 else raw_output,
        )

    def get_test_file_extension(self) -> str:
        """Return C test file extension."""
        return ".c"

    def get_source_file_extension(self) -> str:
        """Return C source file extension."""
        return ".c"

    def normalize_test_path(self, file_path: str, workspace: Path) -> Path:
        """Normalize test path for C projects."""
        p = Path(file_path)

        if p.is_absolute():
            p = Path(p.name)

        normalized = p.as_posix().lstrip("/")

        # Strip leading test directories
        for prefix in ["tests/", "test/"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break

        # Ensure proper extension
        if not normalized.endswith(".c"):
            normalized = normalized + ".c"

        # Ensure test_ prefix
        name = Path(normalized).name
        if not name.startswith("test_"):
            parent = Path(normalized).parent
            normalized = str(parent / f"test_{name}") if str(parent) != "." else f"test_{name}"

        return workspace / "tests" / "poc" / normalized

    def get_allowed_patch_directories(self) -> List[str]:
        """Return allowed directories for patching."""
        return ["tests/poc", "test/poc", "tests", "test"]

    def parse_compile_errors(self, output: str) -> List[str]:
        """Parse C compiler error output."""
        errors = []
        for line in output.split("\n"):
            line_stripped = line.strip()
            line_lower = line_stripped.lower()

            if ": error:" in line_lower:
                errors.append(line_stripped)
            elif line_lower.startswith("error:"):
                errors.append(line_stripped)
            elif "undefined reference" in line_lower:
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
        """Get C-specific tool descriptions."""
        descriptions = {
            "write_and_compile": """Write a C test file to the workspace and compile it.

Args:
    file_path: Test file name (e.g., "test_exploit.c" or "poc/test_exploit.c")
    content: C test file content

Returns:
    {"written": bool, "path": str, "compiled": bool, "errors": List[str], "raw_output": str}

Example:
    result = write_and_compile("test_exploit.c", '''
    #include <stdio.h>
    #include <assert.h>
    #include "vulnerable.h"

    int main() {
        // Setup
        struct vulnerable_struct *obj = create_vulnerable();

        // Trigger vulnerability
        int result = trigger_overflow(obj, malicious_input);

        // Assert exploit succeeded
        assert(result != 0 && "Exploit: buffer overflow triggered");

        printf("Test passed: vulnerability confirmed\\n");
        return 0;
    }
    ''')

    if not result["compiled"]:
        # Fix compilation errors in result["errors"]
        pass""",
            "run_test": """Run C tests using detected build system (ctest, make test, or direct execution).

Args:
    match_contract: Filter by test executable name
    match_test: Filter by test name (ctest -R flag)
    verbosity: Verbosity level
    additional_args: Extra test arguments
    framework_kwargs: Optional dict for C-specific options

Returns:
    {
        "success": bool,
        "tests_passed": int,
        "tests_failed": int,
        "parsed_results": Dict[str, str],
        "raw_output": str
    }

Example:
    result = run_test(match_test="exploit")

    if result["tests_passed"] > 0:
        print("Exploit test passed - vulnerability confirmed!")""",
            "register_exploit": """Register an exploit finding for C.

Args:
    exploit_found: True if you found a way to exploit the vulnerability
    reasoning: Explanation of your analysis and conclusion
    poc_path: Path to the PoC test file (e.g., "tests/poc/test_exploit.c")
    poc_code: Full C code of the PoC

Example:
    register_exploit(
        exploit_found=True,
        reasoning="The strcpy in parse_input() has no bounds checking...",
        poc_path="tests/poc/test_buffer_overflow.c",
        poc_code='''
#include <stdio.h>
#include <string.h>
#include "vulnerable.h"

int main() {
    char payload[256];
    memset(payload, 'A', 256);

    // Trigger buffer overflow
    parse_input(payload);

    // If we reach here, the overflow was triggered
    printf("Exploit successful\\n");
    return 0;
}
'''
    )""",
        }
        return descriptions.get(tool_name)

    def get_poc_guidance(self) -> str:
        """Get C-specific PoC writing guidance."""
        return """## PoC Format: C
Write C test files in tests/poc/.
- Include REAL headers from the codebase
- Use assert() or return codes to prove the exploit
- A test that compiles and demonstrates the vulnerability = valid exploit
- For memory corruption, show the corrupted state
- Return 0 for success, non-zero for failure"""

    def _parse_ctest_output(self, output: str) -> dict:
        """Parse ctest output to extract results."""
        import re

        tests_passed = 0
        tests_failed = 0
        assertion_failures: List[str] = []
        parsed_results: dict = {}

        # CTest summary: "X% tests passed, Y tests failed out of Z"
        summary_match = re.search(r"(\d+)% tests passed.*?(\d+) tests failed out of (\d+)", output)
        if summary_match:
            failed = int(summary_match.group(2))
            total = int(summary_match.group(3))
            tests_passed = total - failed
            tests_failed = failed

        # Individual test results
        for line in output.split("\n"):
            if "Passed" in line:
                test_name = line.split(":")[0].strip() if ":" in line else "unknown"
                parsed_results[test_name] = "pass"
            elif "***Failed" in line or "FAILED" in line:
                test_name = line.split(":")[0].strip() if ":" in line else "unknown"
                parsed_results[test_name] = "fail"
                if "assert" in output.lower():
                    assertion_failures.append(test_name)

        return {
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "assertion_failures": assertion_failures,
            "parsed_results": parsed_results,
        }
