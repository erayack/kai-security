"""Tests for kai.dependency.builder — TreeSitterBuilder."""

from __future__ import annotations

from pathlib import Path

import pytest

from kai.definitions.exploit.tools import make_graph_tools
from kai.dependency.builder import LANG_CONFIGS, TreeSitterBuilder
from kai.dependency.models import NodeKind


class TestParserLoading:
    """Every language in LANG_CONFIGS must have a loadable parser."""

    @pytest.mark.parametrize("lang", list(LANG_CONFIGS.keys()))
    def test_create_parser(self, lang: str) -> None:
        builder = TreeSitterBuilder()
        parser = builder._create_parser(lang)
        assert parser is not None


# ── Solidity ─────────────────────────────────────────────────────

SIMPLE_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IERC20.sol";

contract Vault {
    uint256 public totalShares;

    function deposit(uint256 amount) external {
        totalShares += amount;
    }

    function withdraw(uint256 shares) external {
        totalShares -= shares;
    }
}
"""

SOL_WITH_INHERITANCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Token is IERC20 {
    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }
}
"""

SOL_WITH_STRUCTS = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Registry {
    struct Entry {
        address addr;
        uint256 weight;
    }

    enum Status { Active, Paused }

    event Registered(address indexed addr);

    mapping(address => Entry) public entries;

    function register(address addr, uint256 weight) external {
        entries[addr] = Entry(addr, weight);
        emit Registered(addr);
    }
}
"""


class TestSolidityIndexing:
    """TreeSitterBuilder must index .sol files correctly."""

    def test_finds_sol_files(self, tmp_path: Path) -> None:
        (tmp_path / "Vault.sol").write_text(SIMPLE_SOL)
        (tmp_path / "README.md").write_text("# readme")
        graph = TreeSitterBuilder(languages=["solidity"]).build(tmp_path)
        files = [graph.node(nid).name for nid in graph.nodes(NodeKind.FILE)]
        assert files == ["Vault.sol"]

    def test_extracts_contract(self, tmp_path: Path) -> None:
        (tmp_path / "Vault.sol").write_text(SIMPLE_SOL)
        graph = TreeSitterBuilder(languages=["solidity"]).build(tmp_path)
        containers = graph.find_containers("Vault")
        assert len(containers) == 1
        assert "Vault" in containers[0]

    def test_extracts_functions(self, tmp_path: Path) -> None:
        (tmp_path / "Vault.sol").write_text(SIMPLE_SOL)
        graph = TreeSitterBuilder(languages=["solidity"]).build(tmp_path)
        units = graph.find_units("deposit")
        assert len(units) == 1
        units2 = graph.find_units("withdraw")
        assert len(units2) == 1

    def test_extracts_state_variables(self, tmp_path: Path) -> None:
        (tmp_path / "Vault.sol").write_text(SIMPLE_SOL)
        graph = TreeSitterBuilder(languages=["solidity"]).build(tmp_path)
        var_ids = [
            nid
            for nid in graph.nodes(NodeKind.VARIABLE)
            if "totalShares" in graph.node(nid).name
        ]
        assert len(var_ids) == 1

    def test_extracts_imports(self, tmp_path: Path) -> None:
        (tmp_path / "Vault.sol").write_text(SIMPLE_SOL)
        graph = TreeSitterBuilder(languages=["solidity"]).build(tmp_path)
        imports = list(graph.nodes(NodeKind.IMPORT))
        assert len(imports) >= 1
        text = graph.node(imports[0]).name
        assert "IERC20" in text

    def test_extracts_inheritance(self, tmp_path: Path) -> None:
        (tmp_path / "Token.sol").write_text(SOL_WITH_INHERITANCE)
        graph = TreeSitterBuilder(languages=["solidity"]).build(tmp_path)
        containers = graph.find_containers("Token")
        assert len(containers) == 1

    def test_extracts_structs_enums_events(self, tmp_path: Path) -> None:
        (tmp_path / "Registry.sol").write_text(SOL_WITH_STRUCTS)
        graph = TreeSitterBuilder(languages=["solidity"]).build(tmp_path)

        type_defs = {graph.node(nid).name for nid in graph.nodes(NodeKind.TYPE_DEF)}
        assert "Entry" in type_defs
        assert "Status" in type_defs
        assert "Registered" in type_defs

    def test_skips_test_dirs(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "Vault.sol").write_text(SIMPLE_SOL)
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "Vault.t.sol").write_text(SIMPLE_SOL)
        graph = TreeSitterBuilder(languages=["solidity"]).build(tmp_path)
        files = [graph.node(nid).name for nid in graph.nodes(NodeKind.FILE)]
        assert "Vault.sol" in files
        assert "Vault.t.sol" not in files


# ── Go ───────────────────────────────────────────────────────────

SIMPLE_GO = """\
package main

import "fmt"

type Server struct {
    host string
    port int
}

func (s *Server) Start() {
    fmt.Println("starting")
}

func NewServer(host string, port int) *Server {
    return &Server{host: host, port: port}
}
"""


class TestGoIndexing:
    def test_finds_go_files(self, tmp_path: Path) -> None:
        (tmp_path / "main.go").write_text(SIMPLE_GO)
        graph = TreeSitterBuilder(languages=["go"]).build(tmp_path)
        files = [graph.node(nid).name for nid in graph.nodes(NodeKind.FILE)]
        assert files == ["main.go"]

    def test_extracts_imports(self, tmp_path: Path) -> None:
        (tmp_path / "main.go").write_text(SIMPLE_GO)
        graph = TreeSitterBuilder(languages=["go"]).build(tmp_path)
        imports = list(graph.nodes(NodeKind.IMPORT))
        assert len(imports) >= 1

    def test_extracts_functions(self, tmp_path: Path) -> None:
        (tmp_path / "main.go").write_text(SIMPLE_GO)
        graph = TreeSitterBuilder(languages=["go"]).build(tmp_path)
        units = graph.find_units("NewServer")
        assert len(units) == 1


# ── Rust ─────────────────────────────────────────────────────────

SIMPLE_RUST = """\
use std::collections::HashMap;

struct Config {
    name: String,
    values: HashMap<String, i32>,
}

impl Config {
    fn new(name: String) -> Self {
        Config {
            name,
            values: HashMap::new(),
        }
    }

    fn get(&self, key: &str) -> Option<&i32> {
        self.values.get(key)
    }
}

fn main() {
    let cfg = Config::new("test".to_string());
    println!("{:?}", cfg.get("key"));
}
"""


class TestRustIndexing:
    def test_finds_rs_files(self, tmp_path: Path) -> None:
        (tmp_path / "main.rs").write_text(SIMPLE_RUST)
        graph = TreeSitterBuilder(languages=["rust"]).build(tmp_path)
        files = [graph.node(nid).name for nid in graph.nodes(NodeKind.FILE)]
        assert files == ["main.rs"]

    def test_extracts_struct(self, tmp_path: Path) -> None:
        (tmp_path / "main.rs").write_text(SIMPLE_RUST)
        graph = TreeSitterBuilder(languages=["rust"]).build(tmp_path)
        containers = graph.find_containers("Config")
        assert len(containers) >= 1

    def test_extracts_functions(self, tmp_path: Path) -> None:
        (tmp_path / "main.rs").write_text(SIMPLE_RUST)
        graph = TreeSitterBuilder(languages=["rust"]).build(tmp_path)
        units = graph.find_units("main")
        assert len(units) >= 1


# ── Multi-language ───────────────────────────────────────────────


class TestMultiLanguage:
    """Builder with default config should index all languages together."""

    def test_indexes_all_languages(self, tmp_path: Path) -> None:
        (tmp_path / "Vault.sol").write_text(SIMPLE_SOL)
        (tmp_path / "main.go").write_text(SIMPLE_GO)
        (tmp_path / "main.rs").write_text(SIMPLE_RUST)
        (tmp_path / "app.py").write_text("def hello():\n    pass\n")

        graph = TreeSitterBuilder().build(tmp_path)
        files = sorted(graph.node(nid).name for nid in graph.nodes(NodeKind.FILE))
        assert "Vault.sol" in files
        assert "main.go" in files
        assert "main.rs" in files
        assert "app.py" in files


# ── Parameter extraction ─────────────────────────────────────────

PYTHON_TYPED = """\
def parse_xml(raw_input: str, timeout: int = 30) -> dict:
    pass

class Handler:
    def handle(self, request: bytes) -> None:
        pass

    def _private(self):
        pass
"""

PYTHON_NO_PARAMS = """\
def noop():
    pass
"""

PYTHON_SPLAT = """\
def variadic(*args, **kwargs):
    pass
"""


class TestPythonParamExtraction:
    def test_typed_params(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_TYPED)
        graph = TreeSitterBuilder(languages=["python"]).build(tmp_path)
        units = graph.find_units("parse_xml")
        assert len(units) == 1
        node = graph.node(units[0])
        params = node.meta.get("params", [])
        assert len(params) == 2
        assert params[0] == {"name": "raw_input", "type": "str"}
        assert params[1]["name"] == "timeout"
        assert params[1]["type"] == "int"

    def test_no_params(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_NO_PARAMS)
        graph = TreeSitterBuilder(languages=["python"]).build(tmp_path)
        units = graph.find_units("noop")
        assert len(units) == 1
        node = graph.node(units[0])
        assert node.meta.get("params", []) == []

    def test_self_param(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_TYPED)
        graph = TreeSitterBuilder(languages=["python"]).build(tmp_path)
        units = graph.find_units("handle")
        assert len(units) == 1
        params = graph.node(units[0]).meta.get("params", [])
        assert params[0] == {"name": "self"}
        assert params[1] == {"name": "request", "type": "bytes"}

    def test_untyped_self(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_TYPED)
        graph = TreeSitterBuilder(languages=["python"]).build(tmp_path)
        units = graph.find_units("_private")
        assert len(units) == 1
        params = graph.node(units[0]).meta.get("params", [])
        assert params == [{"name": "self"}]

    def test_splat_params(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_SPLAT)
        graph = TreeSitterBuilder(languages=["python"]).build(tmp_path)
        units = graph.find_units("variadic")
        assert len(units) == 1
        params = graph.node(units[0]).meta.get("params", [])
        names = [p["name"] for p in params]
        assert "*args" in names
        assert "**kwargs" in names


class TestGoParamExtraction:
    def test_typed_params(self, tmp_path: Path) -> None:
        (tmp_path / "main.go").write_text(SIMPLE_GO)
        graph = TreeSitterBuilder(languages=["go"]).build(tmp_path)
        units = graph.find_units("NewServer")
        assert len(units) == 1
        params = graph.node(units[0]).meta.get("params", [])
        assert len(params) == 2
        assert params[0]["name"] == "host"
        assert params[1]["name"] == "port"


JS_FUNCS = """\
function greet(name, age) {
    console.log(name + age);
}
"""


class TestJSParamExtraction:
    def test_js_params(self, tmp_path: Path) -> None:
        (tmp_path / "app.js").write_text(JS_FUNCS)
        graph = TreeSitterBuilder(languages=["javascript"]).build(tmp_path)
        units = graph.find_units("greet")
        assert len(units) == 1
        params = graph.node(units[0]).meta.get("params", [])
        assert len(params) == 2
        assert params[0] == {"name": "name"}
        assert params[1] == {"name": "age"}


# ── dep_signatures tool ──────────────────────────────────────────


class TestDepSignatures:
    def test_returns_correct_structure(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_TYPED)
        graph = TreeSitterBuilder(languages=["python"]).build(tmp_path)
        tools = make_graph_tools(graph)
        sigs = tools["dep_signatures"]("app.py")
        assert len(sigs) >= 3  # parse_xml, handle, _private
        by_name = {s["name"]: s for s in sigs}
        assert "parse_xml" in by_name
        sig = by_name["parse_xml"]
        assert "id" in sig
        assert "span" in sig
        assert sig["params"][0] == {"name": "raw_input", "type": "str"}

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_TYPED)
        graph = TreeSitterBuilder(languages=["python"]).build(tmp_path)
        tools = make_graph_tools(graph)
        assert tools["dep_signatures"]("nonexistent.py") == []
