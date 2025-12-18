# Kai Adapter System

Kai uses a three-layer adapter pattern to support multiple smart contract frameworks and languages. Each adapter type handles a different concern:

| Adapter Type | Location | Purpose |
|-------------|----------|---------|
| **Tool Adapter** | `kai/utils/tool_adapters/` | Compile code, run tests, parse outputs |
| **Workspace Adapter** | `kai/utils/workspace/` | Provision agent workspaces with correct project structure |
| **Domain Adapter** | `kai/utils/dependency/adapters/` | Semantic understanding (entrypoints, state vars, access control) |

```
┌─────────────────────────────────────────────────────────────────┐
│                         StateAgent                               │
├─────────────────────────────────────────────────────────────────┤
│  Tools (write_and_compile, run_test)  ←── ToolAdapter           │
│  Workspace provisioning               ←── WorkspaceAdapter       │
│  Graph queries (is_entrypoint, etc.)  ←── DomainAdapter          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. Tool Adapters

**Purpose**: Framework-specific compilation and test execution.

**Location**: `kai/utils/tool_adapters/`

### Base Class

```python
# kai/utils/tool_adapters/base.py
class ToolAdapter(ABC):
    @property
    def framework_name(self) -> str: ...      # "foundry", "hardhat", "anchor"
    @property
    def language(self) -> str: ...            # "solidity", "rust"

    def find_binary(self) -> str: ...         # Find compiler/test runner
    def compile(workspace_path, timeout) -> CompileResult: ...
    def run_test(workspace_path, match_contract, match_test, ...) -> TestResult: ...

    def get_test_file_extension(self) -> str: ...    # ".t.sol", "_test.rs"
    def get_source_file_extension(self) -> str: ...  # ".sol", ".rs"
    def normalize_test_path(file_path, workspace) -> Path: ...
    def get_allowed_patch_directories(self) -> List[str]: ...
    def get_tool_description(tool_name) -> Optional[str]: ...  # LLM tool descriptions
```

### Adding a New Tool Adapter

**Example: Adding Hardhat support**

```python
# kai/utils/tool_adapters/hardhat.py
from kai.utils.tool_adapters.base import ToolAdapter, CompileResult, TestResult

class HardhatToolAdapter(ToolAdapter):
    @property
    def framework_name(self) -> str:
        return "hardhat"

    @property
    def language(self) -> str:
        return "solidity"

    def find_binary(self) -> str:
        # Check for npx hardhat
        if shutil.which("npx"):
            return "npx hardhat"
        raise FileNotFoundError("npx not found - is Node.js installed?")

    def compile(self, workspace_path: Path, timeout: int = 120) -> CompileResult:
        result = subprocess.run(
            ["npx", "hardhat", "compile"],
            cwd=str(workspace_path),
            capture_output=True, text=True, timeout=timeout
        )
        return CompileResult(
            success=result.returncode == 0,
            errors=self.parse_compile_errors(result.stderr),
            raw_output=result.stdout + result.stderr
        )

    def run_test(self, workspace_path: Path, ...) -> TestResult:
        cmd = ["npx", "hardhat", "test"]
        if match_test:
            cmd.extend(["--grep", match_test])
        # ... run and parse

    def get_test_file_extension(self) -> str:
        return ".test.js"  # or ".test.ts"

    def get_source_file_extension(self) -> str:
        return ".sol"

    def get_allowed_patch_directories(self) -> List[str]:
        return ["test/poc", "test/exploits"]  # Hardhat conventions

    def get_tool_description(self, tool_name: str) -> Optional[str]:
        descriptions = {
            "write_and_compile": """Write a Solidity test file and compile with Hardhat.

Args:
    file_path: Test file name (e.g., "MyExploit.test.js")
    content: JavaScript/TypeScript test content using ethers.js

Example:
    result = write_and_compile("Exploit.test.js", '''
    const { expect } = require("chai");
    const { ethers } = require("hardhat");

    describe("Exploit", function() {
        it("should drain funds", async function() {
            // ... exploit logic
        });
    });
    ''')
""",
            # ... other tools
        }
        return descriptions.get(tool_name)
```

**Register in `__init__.py`:**

```python
# kai/utils/tool_adapters/__init__.py
from kai.utils.tool_adapters.hardhat import HardhatToolAdapter

_ADAPTERS: Dict[str, Type[ToolAdapter]] = {
    "foundry": FoundryToolAdapter,
    "hardhat": HardhatToolAdapter,  # Add here
}
```

### Caveats & Tips

1. **LLM Tool Descriptions**: The `get_tool_description()` method is critical - LLMs use these descriptions to understand how to call tools. Make examples framework-specific.

2. **ADAPTER_DESCRIBED_TOOLS**: Tools that need framework-specific descriptions must be registered in `kai/agents/tools/tools.py`:
   ```python
   ADAPTER_DESCRIBED_TOOLS = {"write_and_compile", "run_test", "patch_file", "register_exploit"}
   ```

3. **Binary Discovery**: Always check multiple paths (PATH, common install locations). Users may have non-standard setups.

4. **Timeout Handling**: Compilation can hang. Always use timeouts.

5. **Output Parsing**: Test output formats vary wildly. Parse conservatively and include `raw_output` for debugging.

---

## 2. Workspace Adapters

**Purpose**: Provision isolated workspaces for agents to write and compile PoC tests.

**Location**: `kai/utils/workspace/`

### Base Class

```python
# kai/utils/workspace/base.py
class WorkspaceAdapter(ABC):
    @property
    def framework_name(self) -> str: ...

    def provision_lightweight(workspace, master, master_context, logger) -> str:
        """Create workspace with remappings to master (no file copy)."""
        ...

    def provision_full(workspace, master, master_context, preset, logger) -> str:
        """Create workspace by copying files from master."""
        ...

    def detect_remappings(master: Path) -> str:
        """Generate import remappings pointing to master."""
        ...

    def infer_src_path(master: Path) -> Path:
        """Infer source directory (src/, contracts/, etc.)."""
        ...
```

### Adding a New Workspace Adapter

**Example: Adding Hardhat support**

```python
# kai/utils/workspace/hardhat.py
class HardhatWorkspaceAdapter(WorkspaceAdapter):
    @property
    def framework_name(self) -> str:
        return "hardhat"

    def provision_lightweight(self, workspace, master, master_context, logger=None):
        # Create hardhat.config.js with path mappings
        config = f'''
require("@nomicfoundation/hardhat-toolbox");

module.exports = {{
  solidity: "0.8.20",
  paths: {{
    sources: "{master / 'contracts'}",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }}
}};
'''
        (workspace / "hardhat.config.js").write_text(config)
        (workspace / "test").mkdir(exist_ok=True)

        # Copy package.json if exists
        if (master / "package.json").exists():
            shutil.copy(master / "package.json", workspace / "package.json")

        return str(workspace)

    def provision_full(self, workspace, master, master_context, preset, logger=None):
        # Copy contracts, test, and config
        dirs_to_copy = ["contracts", "node_modules"]
        for d in dirs_to_copy:
            if (master / d).exists():
                shutil.copytree(master / d, workspace / d)

        # Copy config files
        for f in ["hardhat.config.js", "hardhat.config.ts", "package.json"]:
            if (master / f).exists():
                shutil.copy(master / f, workspace / f)

        (workspace / "test").mkdir(exist_ok=True)
        return str(workspace)

    def detect_remappings(self, master: Path) -> str:
        # Hardhat uses path mappings in config, not remappings.txt
        return ""

    def infer_src_path(self, master: Path) -> Path:
        if (master / "contracts").exists():
            return master / "contracts"
        return master / "src"
```

**Register in `__init__.py`:**

```python
# kai/utils/workspace/__init__.py
from kai.utils.workspace.hardhat import HardhatWorkspaceAdapter

def get_workspace_adapter(framework: str) -> WorkspaceAdapter:
    adapters = {
        "foundry": FoundryWorkspaceAdapter,
        "hardhat": HardhatWorkspaceAdapter,  # Add here
    }
    ...
```

### Caveats & Tips

1. **LIGHTWEIGHT vs FULL**:
   - `LIGHTWEIGHT`: Uses symlinks/remappings. Fast, but may have path issues.
   - `FULL`: Copies everything. Slower but more isolated.

2. **Remappings**: Foundry uses `remappings.txt`, Hardhat uses `paths` in config. Handle appropriately.

3. **Dependencies**: Some frameworks need `node_modules` (Hardhat) or `lib/` (Foundry). Don't forget these.

4. **forge-std**: For Foundry, always symlink `forge-std` to the workspace.

5. **Path Resolution**: The workspace test files import from master. Ensure remappings resolve correctly:
   ```
   workspace/test/Exploit.t.sol  →  imports "src/Vault.sol"
   remapping: src/=<master>/src/
   ```

---

## 3. Domain Adapters

**Purpose**: Language-specific semantic understanding for security analysis.

**Location**: `kai/utils/dependency/adapters/`

### Base Class

```python
# kai/utils/dependency/adapters/base.py
class DomainAdapter(ABC):
    @property
    def name(self) -> str: ...

    def get_domain_mapping(self) -> Dict[str, str]:
        """Map generic NodeKinds to domain terms (CONTAINER → 'Contract')."""
        ...

    def is_public_entrypoint(self, node: Node) -> bool:
        """Is this callable by external attackers?"""
        ...

    def is_state_variable(self, node: Node) -> bool:
        """Does this represent persistent state?"""
        ...

    def is_test_file(self, file_path: str) -> bool: ...
    def is_library_file(self, file_path: str) -> bool: ...

    def resolve_symbol(self, name, context_graph, scope=None) -> List[str]:
        """Fuzzy-match user input to node IDs."""
        ...

    def is_non_auth_guard(self, modifier_name: str) -> bool:
        """Is this a non-auth modifier (reentrancy, pause)?"""
        ...

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """Determine trust level from modifiers."""
        ...
```

### Adding a New Domain Adapter

**Example: Adding Rust/Anchor support**

```python
# kai/utils/dependency/adapters/anchor.py
class AnchorAdapter(DomainAdapter):
    @property
    def name(self) -> str:
        return "anchor"

    def get_domain_mapping(self) -> Dict[str, str]:
        return {
            "CONTAINER": "Program",
            "UNIT": "Instruction",
            "VARIABLE": "Account",
        }

    def is_public_entrypoint(self, node: Node) -> bool:
        # Anchor instruction handlers are entrypoints
        if node.kind != NodeKind.UNIT:
            return False
        # Check for #[instruction] attribute or pub fn in instruction module
        return "instruction" in (node.modifiers or []) or node.visibility == "public"

    def is_state_variable(self, node: Node) -> bool:
        # PDA accounts are state
        return node.kind == NodeKind.VARIABLE and "account" in (node.type_ref or "").lower()

    def is_test_file(self, file_path: str) -> bool:
        return "_test.rs" in file_path or "/tests/" in file_path

    def is_library_file(self, file_path: str) -> bool:
        lib_patterns = [
            "anchor-lang", "solana-program", ".cargo/registry"
        ]
        return any(p in file_path for p in lib_patterns)

    def is_non_auth_guard(self, modifier_name: str) -> bool:
        non_auth = {"require_keys_eq", "require_keys_neq"}
        return modifier_name.lower() in non_auth

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        # Anchor uses constraints like has_one, constraint
        if any("has_one" in m or "signer" in m for m in modifier_names):
            return "medium"
        return "low"
```

**Register in `__init__.py`:**

```python
# kai/utils/dependency/adapters/__init__.py
from .anchor import AnchorAdapter

AdapterType = Literal["solidity", "anchor"]

ADAPTER_REGISTRY: dict[AdapterType, type[DomainAdapter]] = {
    "solidity": SolidityAdapter,
    "anchor": AnchorAdapter,  # Add here
}
```

### Caveats & Tips

1. **Visibility Rules**: Each language has different visibility semantics:
   - Solidity: `public`/`external` are entrypoints
   - Rust: `pub fn` in specific modules
   - Vyper: No `internal` keyword means public

2. **Library Detection**: Critical for filtering. Include all common dependency paths:
   - Solidity: `lib/`, `node_modules/`, `@openzeppelin/`, `forge-std/`
   - Rust: `.cargo/registry/`, `target/`

3. **Symbol Resolution**: Users type fuzzy names ("withdraw", "Vault.deposit"). Handle:
   - Partial matches
   - Case insensitivity
   - Overloaded functions

4. **Trust Levels**: Map to consistent levels across languages:
   - `"high"`: Only owner/admin
   - `"medium"`: Role-based
   - `"low"`: Any authenticated user
   - `"none"`: Anyone (no auth)

---

## Framework Detection

The system auto-detects frameworks via `MasterContext.frameworks` or config files:

```python
# kai/dispatcher/workspace.py
def _detect_framework(self, master: Path, master_context=None) -> str:
    if master_context and master_context.frameworks:
        return master_context.frameworks[0].lower()

    if (master / "foundry.toml").exists():
        return "foundry"
    if (master / "hardhat.config.js").exists():
        return "hardhat"
    if (master / "Anchor.toml").exists():
        return "anchor"

    return "foundry"  # Default
```

**To add detection for your framework**, update this method and ensure your framework's config file is checked.

---

## Checklist for Adding a New Framework

### Minimum Viable Support

- [ ] **Tool Adapter**: `kai/utils/tool_adapters/<framework>.py`
  - [ ] `compile()` - Run compiler
  - [ ] `run_test()` - Run tests
  - [ ] `get_tool_description()` - LLM-friendly descriptions
  - [ ] Register in `__init__.py`

- [ ] **Workspace Adapter**: `kai/utils/workspace/<framework>.py`
  - [ ] `provision_lightweight()` - Minimal workspace
  - [ ] `detect_remappings()` - Import path setup
  - [ ] Register in `__init__.py`

### Full Support (recommended)

- [ ] **Domain Adapter**: `kai/utils/dependency/adapters/<domain>.py`
  - [ ] `is_public_entrypoint()` - Attack surface detection
  - [ ] `is_library_file()` - Filter non-protocol code
  - [ ] `get_trust_for_modifiers()` - Access control analysis
  - [ ] Register in `__init__.py`

- [ ] **Update MasterContext schema** if needed:
  - [ ] Add to `AdapterType` literal in `kai/schemas.py`
  - [ ] Add framework to `frameworks` field

- [ ] **Tests**:
  - [ ] Unit tests for each adapter
  - [ ] Integration test with sample project

---

## Common Patterns

### Singleton Adapter Caching

```python
_ADAPTER_CACHE: Dict[str, ToolAdapter] = {}

def get_tool_adapter(framework: str) -> ToolAdapter:
    if framework not in _ADAPTER_CACHE:
        _ADAPTER_CACHE[framework] = _ADAPTERS[framework]()
    return _ADAPTER_CACHE[framework]
```

### Getting Adapter from Agent Context

```python
# In BaseAgent
def get_tool_adapter(self):
    from kai.utils.tool_adapters import get_tool_adapter, get_supported_frameworks

    master_context = getattr(self, "master_context", None)
    if master_context:
        frameworks = getattr(master_context, "frameworks", None) or []
        supported = set(get_supported_frameworks())
        for fw in frameworks:
            if fw.lower() in supported:
                return get_tool_adapter(fw.lower())

    return get_tool_adapter("foundry")  # Default
```

### Framework-Specific Tool Descriptions

Tools in `ADAPTER_DESCRIBED_TOOLS` get their descriptions from the adapter:

```python
# kai/agents/utils.py
def generate_openai_tools(tools_module: str, adapter=None):
    for tool_fn in tools:
        if tool_fn.__name__ in ADAPTER_DESCRIBED_TOOLS and adapter:
            desc = adapter.get_tool_description(tool_fn.__name__)
            if desc:
                tool_schema["function"]["description"] = desc
```

---

## Testing Adapters

```python
# tests/test_adapters.py
def test_foundry_tool_adapter():
    adapter = get_tool_adapter("foundry")
    assert adapter.framework_name == "foundry"
    assert adapter.language == "solidity"
    assert adapter.get_test_file_extension() == ".t.sol"

def test_workspace_adapter():
    adapter = get_workspace_adapter("foundry")
    workspace = Path("/tmp/test_workspace")
    master = Path("/path/to/project")

    result = adapter.provision_lightweight(workspace, master, mock_context)
    assert (workspace / "foundry.toml").exists()
    assert (workspace / "test").exists()

def test_domain_adapter():
    adapter = get_adapter("solidity")

    # Test entrypoint detection
    public_fn = Node(kind=NodeKind.UNIT, visibility="public")
    assert adapter.is_public_entrypoint(public_fn) == True

    internal_fn = Node(kind=NodeKind.UNIT, visibility="internal")
    assert adapter.is_public_entrypoint(internal_fn) == False
```