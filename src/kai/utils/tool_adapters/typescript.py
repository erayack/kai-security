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

        # Strip leading test directories
        for prefix in ["tests/", "test/", "__tests__/", "src/"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break

        # Ensure .test.ts extension
        stem = Path(normalized).stem
        if stem.endswith(".test"):
            stem = stem[:-5]

        return workspace / "tests" / f"{stem}.test.ts"

    def get_poc_guidance(self) -> str:
        """Return TypeScript-specific PoC guidance."""
        return """## PoC Format: TypeScript
Write TypeScript test files in tests/poc/ with .mts extension (ES modules).

**CRITICAL: Use framework-agnostic code. Do NOT use:**
- describe(), it(), test() - These are Mocha/Jest globals that won't work
- expect(), chai - These require installation
- jest.mock(), vi.mock() - These are framework-specific

**Correct PoC structure:**
```typescript
import assert from 'assert';

// IMPORT RULES:
// 1. PREFERRED: Import from package name
import targetModule from 'package-name';
// 2. FALLBACK: Import from dist/
// import targetModule from '../dist/index.js';
// 3. WRONG: Do NOT import from src/
// import targetModule from '../src/index.ts';  // WRONG!

// Test directly - NO describe/it blocks
const result = targetModule(maliciousInput);

// Use node:assert for assertions
assert.strictEqual(result.property, expected, 'Exploit demonstrated');

console.log('PoC PASSED: vulnerability confirmed');
process.exit(0);  // Exit 0 = success
```

**Import path rules:**
1. Check package.json "main" or "exports" for entry point
2. Prefer package name: `import x from 'package-name'`
3. If relative path needed, use dist/: `import x from '../dist/index.js'`
4. Include .js extension in relative imports (even for .ts source)

**Key rules:**
- Use .mts extension for TypeScript ES modules
- Use `import assert from 'assert'` for assertions
- Exit with code 0 = exploit succeeded
- For TypeScript PoCs, ensure tsconfig.json has compatible module settings
"""
