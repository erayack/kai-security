"""
TypeScript tool adapter.

Extends the JavaScript adapter with TypeScript-specific behavior for:
- File extensions (.ts, .tsx)
- TypeScript-specific test patterns
- Language identification
"""

from pathlib import Path

from kai.utils.tool_adapters.javascript import JavaScriptToolAdapter


class TypeScriptToolAdapter(JavaScriptToolAdapter):
    """
    Tool adapter for TypeScript projects.

    Extends JavaScriptToolAdapter since TypeScript projects use the same
    tooling (npm/yarn/pnpm, Jest/Vitest/Mocha) but with TypeScript-specific
    file extensions and compilation.
    """

    @property
    def framework_name(self) -> str:
        return "typescript"

    @property
    def language(self) -> str:
        return "typescript"

    def get_test_file_extension(self) -> str:
        """Return TypeScript test file extension."""
        return ".test.ts"

    def get_source_file_extension(self) -> str:
        """Return TypeScript source file extension."""
        return ".ts"

    def normalize_test_path(self, file_path: str, workspace: Path) -> Path:
        """Normalize test path for TypeScript projects."""
        p = Path(file_path)

        if p.is_absolute():
            try:
                p = p.relative_to(workspace)
            except ValueError:
                pass

        normalized = p.as_posix().lstrip("/")

        # Strip leading test directories but preserve poc/ subdirectory
        for prefix in ["tests/poc/", "test/poc/", "__tests__/poc/"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
                # Preserve .mts extension for ES modules (needed for ESM imports)
                if normalized.endswith(".mts"):
                    return workspace / "tests" / "poc" / normalized
                break

        for prefix in ["tests/", "test/", "__tests__/", "src/"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
                break

        # Preserve .mts extension for ES modules (needed for ESM imports)
        if normalized.endswith(".mts"):
            stem = Path(normalized).stem
            return workspace / "tests" / "poc" / f"{stem}.mts"

        # Default: Ensure .test.ts extension
        stem = Path(normalized).stem
        if stem.endswith(".test"):
            stem = stem[:-5]

        return workspace / "tests" / f"{stem}.test.ts"

    def get_poc_guidance(self) -> str:
        """Return TypeScript-specific PoC guidance."""
        return """## PoC Format: TypeScript
Write TypeScript test files in tests/poc/ with .ts extension.
Files are executed directly with Bun (native TypeScript support).

**CRITICAL: Use framework-agnostic code. Do NOT use:**
- describe(), it(), test() - These are Mocha/Jest globals that won't work
- expect(), chai - These require installation
- jest.mock(), vi.mock() - These are framework-specific

**Correct PoC structure:**
```typescript
import assert from 'assert';

// IMPORT RULES (from tests/poc/):
// 1. PREFERRED: Import from src/ directly (Bun runs TypeScript natively)
import { targetFunction } from '../../src/module.ts';
// 2. ALTERNATIVE: Import from package name (if installed)
// import targetModule from 'package-name';

// Test directly - NO describe/it blocks
const result = targetFunction(maliciousInput);

// Use node:assert for assertions
assert.strictEqual(result.property, expected, 'Exploit demonstrated');

console.log('PoC PASSED: vulnerability confirmed');
process.exit(0);  // Exit 0 = success
```

**Import path rules:**
1. Import directly from src/ TypeScript files (Bun supports this)
2. Use relative paths from tests/poc/: ../../src/...
3. Include .ts extension in imports

**Key rules:**
- Use .ts extension for TypeScript files
- Use `import assert from 'assert'` for assertions
- Exit with code 0 = exploit succeeded
- Bun runs TypeScript directly - no compilation needed
"""
