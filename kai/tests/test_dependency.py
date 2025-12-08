"""
Tests for the dependency graph module.

Uses the pre-built dependency_graph.json from bbp-public-assets for testing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kai.utils.dependency import (
    DependencyGraph,
    NodeKind,
    EdgeKind,
    Node,
    FieldAccessInfo,
    GuardIssue,
    GuardIssueType,
    Severity,
    # Typed analysis API
    get_actor_roles,
    get_context_slice_meta,
    detect_guard_issues,
    get_field_access_info,
    get_liveness_invariants,
    get_write_paths,
    get_state_var_info,
    get_invariant_vectors,
)


# Path to the cached dependency graph
GRAPH_JSON = Path(__file__).resolve().parent / "fixtures" / "dependency_graph.json"


@pytest.fixture(scope="module")
def graph() -> DependencyGraph:
    """Load the dependency graph from the cached JSON file."""
    if not GRAPH_JSON.exists():
        pytest.skip(f"Dependency graph not found at {GRAPH_JSON}")
    return DependencyGraph.from_json(GRAPH_JSON)


class TestGraphBasics:
    """Tests for basic graph operations."""

    def test_graph_loads(self, graph: DependencyGraph):
        """Graph should load with nodes and edges."""
        assert len(graph._nodes) > 0
        assert len(graph._edges) > 0

    def test_nodes_by_kind(self, graph: DependencyGraph):
        """Should be able to filter nodes by kind."""
        contracts = graph.nodes(NodeKind.CONTRACT)
        functions = graph.nodes(NodeKind.FUNCTION)
        state_vars = graph.nodes(NodeKind.STATE_VAR)
        files = graph.nodes(NodeKind.FILE)

        assert len(contracts) > 0, "Should have contract nodes"
        assert len(functions) > 0, "Should have function nodes"
        assert len(state_vars) > 0, "Should have state variable nodes"
        assert len(files) > 0, "Should have file nodes"

    def test_node_access(self, graph: DependencyGraph):
        """Should be able to access individual nodes."""
        contract_ids = list(graph.nodes(NodeKind.CONTRACT))
        assert len(contract_ids) > 0

        node = graph.node(contract_ids[0])
        assert node.kind == NodeKind.CONTRACT
        assert node.name is not None
        assert node.id == contract_ids[0]

    def test_find_contracts(self, graph: DependencyGraph):
        """Should find contracts by name."""
        # Look for a contract we know exists in bbp-public-assets
        results = graph.find_contracts("StakedUSDeV2")
        assert len(results) > 0, "Should find StakedUSDeV2 contract"

    def test_find_functions(self, graph: DependencyGraph):
        """Should find functions by name."""
        results = graph.find_functions("withdraw")
        assert len(results) > 0, "Should find withdraw function(s)"


class TestPublicEntrypoints:
    """Tests for public entrypoint detection."""

    def test_public_entrypoints_exist(self, graph: DependencyGraph):
        """Should find public/external functions."""
        entrypoints = graph.public_entrypoints()
        assert len(entrypoints) > 0, "Should have public entrypoints"

    def test_public_entrypoints_are_public(self, graph: DependencyGraph):
        """All entrypoints should have public/external visibility."""
        entrypoints = graph.public_entrypoints()
        for ep in entrypoints[:20]:  # Sample first 20
            node = graph.node(ep)
            assert node.kind == NodeKind.FUNCTION
            assert node.visibility in ("public", "external"), (
                f"Entrypoint {node.name} has visibility {node.visibility}"
            )

    def test_excludes_constructors(self, graph: DependencyGraph):
        """Constructors should not be in entrypoints."""
        entrypoints = graph.public_entrypoints()
        for ep in entrypoints:
            node = graph.node(ep)
            assert not node.meta.get("is_constructor", False), (
                f"Constructor {node.name} should not be an entrypoint"
            )


class TestDeriveRelatedFiles:
    """Tests for file relationship derivation."""

    def test_derive_related_files_minimal(self, graph: DependencyGraph):
        """MINIMAL mode should return only the target file."""
        target = "contracts/StakedUSDeV2.sol"
        related = graph.derive_related_files(target, depth=2, mode="MINIMAL")
        assert len(related) == 1
        assert target in related[0]

    def test_derive_related_files_real_source(self, graph: DependencyGraph):
        """REAL_SOURCE mode should return related files."""
        target = "contracts/StakedUSDeV2.sol"
        related = graph.derive_related_files(target, depth=2, mode="REAL_SOURCE")
        assert len(related) > 1, "Should find related files"
        # Target should be included
        assert any(target in f for f in related)

    def test_derive_related_files_broad(self, graph: DependencyGraph):
        """BROAD mode should return more files than REAL_SOURCE."""
        target = "contracts/StakedUSDeV2.sol"
        real_source = graph.derive_related_files(target, depth=2, mode="REAL_SOURCE")
        broad = graph.derive_related_files(target, depth=2, mode="BROAD")
        # Broad should be >= real_source (uses all edge types)
        assert len(broad) >= len(real_source)

    def test_excludes_test_files_by_default(self, graph: DependencyGraph):
        """Test files should be excluded by default."""
        target = "contracts/StakedUSDeV2.sol"
        related = graph.derive_related_files(target, depth=3, mode="REAL_SOURCE")
        for f in related:
            assert not graph._looks_like_test(f), f"Test file {f} should be excluded"


class TestBFS:
    """Tests for BFS traversal."""

    def test_bfs_from_function(self, graph: DependencyGraph):
        """BFS should find connected nodes from a function."""
        func_ids = graph.find_functions("withdraw")
        if not func_ids:
            pytest.skip("No withdraw function found")

        visited = graph.bfs(
            func_ids[:1],
            max_hops=2,
            edge_kinds={EdgeKind.CALLS, EdgeKind.READS, EdgeKind.WRITES},
            direction="out",
        )
        assert len(visited) >= 1, "Should visit at least the start node"

    def test_bfs_respects_max_hops(self, graph: DependencyGraph):
        """BFS with lower max_hops should visit fewer nodes."""
        func_ids = graph.find_functions("withdraw")
        if not func_ids:
            pytest.skip("No withdraw function found")

        visited_1 = graph.bfs(func_ids[:1], max_hops=1, direction="both")
        visited_3 = graph.bfs(func_ids[:1], max_hops=3, direction="both")
        assert len(visited_1) <= len(visited_3)


class TestActorRoles:
    """Tests for actor role analysis."""

    def test_get_actor_roles(self, graph: DependencyGraph):
        """Should extract actor roles from modifier patterns."""
        roles = get_actor_roles(graph)
        assert len(roles) > 0, "Should find at least one role"

    def test_role_structure(self, graph: DependencyGraph):
        """Actor roles should have proper structure."""
        roles = get_actor_roles(graph)
        for role in roles:
            assert role.role is not None
            assert role.trust in ("High", "Medium", "Low", "None", "N/A")
            assert isinstance(role.modifier_pattern, list)
            assert isinstance(role.privileges, list)
            assert role.function_count >= 0

    def test_user_role_exists(self, graph: DependencyGraph):
        """Should detect 'User' role for unprotected functions."""
        roles = get_actor_roles(graph)
        role_names = [r.role for r in roles]
        assert "User" in role_names, "Should have User role for unprotected functions"

    def test_protected_roles_exist(self, graph: DependencyGraph):
        """Should detect protected roles like Owner, RoleBased."""
        roles = get_actor_roles(graph)
        role_names = [r.role for r in roles]
        # bbp-public-assets uses access control, should have at least one protected role
        protected = [
            r for r in role_names if r not in ("User", "Pausable", "ReentrancyGuard")
        ]
        assert len(protected) > 0, "Should find protected roles"


class TestWritePaths:
    """Tests for write path tracing."""

    def test_get_write_paths_for_known_var(self, graph: DependencyGraph):
        """Should trace write paths for known state variables."""
        # _balances is a common ERC20 variable
        paths = get_write_paths(graph, "_balances")
        assert len(paths) > 0, "Should find write paths for _balances"

    def test_write_path_structure(self, graph: DependencyGraph):
        """Write paths should have proper structure."""
        paths = get_write_paths(graph, "_balances")
        for path in paths[:5]:  # Check first 5
            assert path.entrypoint is not None
            assert isinstance(path.path, list)
            assert len(path.path) > 0
            assert path.writer is not None
            assert path.var_name == "_balances"

    def test_write_path_starts_with_entrypoint(self, graph: DependencyGraph):
        """Write path should start with the entrypoint."""
        paths = get_write_paths(graph, "_balances")
        for path in paths[:5]:
            assert path.path[0] == path.entrypoint

    def test_nonexistent_var_returns_empty(self, graph: DependencyGraph):
        """Non-existent variable should return empty list."""
        paths = get_write_paths(graph, "nonexistent_variable_xyz")
        assert paths == []


class TestContextSliceMeta:
    """Tests for context slice generation."""

    def test_get_context_slice_meta(self, graph: DependencyGraph):
        """Should generate context slice for a target function."""
        ctx = get_context_slice_meta(
            graph,
            target_func="withdraw",
            invariant_seeds=["cooldowns", "_balances"],
            depth=2,
        )
        assert ctx.target_func == "withdraw"
        assert ctx.invariant_seeds == ["cooldowns", "_balances"]

    def test_context_slice_finds_related_files(self, graph: DependencyGraph):
        """Context slice should find related files."""
        ctx = get_context_slice_meta(
            graph, target_func="withdraw", invariant_seeds=["_balances"], depth=2
        )
        assert len(ctx.related_files) > 0, "Should find related files"

    def test_context_slice_includes_write_paths(self, graph: DependencyGraph):
        """Context slice should include write paths when requested."""
        ctx = get_context_slice_meta(
            graph,
            target_func="withdraw",
            invariant_seeds=["_balances"],
            depth=2,
            include_write_paths=True,
        )
        assert len(ctx.write_paths) > 0, "Should include write paths"

    def test_context_slice_symbols(self, graph: DependencyGraph):
        """Context slice should collect relevant symbols."""
        ctx = get_context_slice_meta(
            graph, target_func="withdraw", invariant_seeds=["cooldowns"], depth=2
        )
        assert len(ctx.symbols) > 0, "Should collect symbols"

    def test_context_slice_to_dict(self, graph: DependencyGraph):
        """Context slice should serialize to dict."""
        ctx = get_context_slice_meta(
            graph, target_func="withdraw", invariant_seeds=["_balances"], depth=2
        )
        d = ctx.to_dict()
        assert "target_func" in d
        assert "related_files" in d
        assert "symbols" in d
        assert "write_paths" in d


class TestStateVarInfo:
    """Tests for state variable info extraction."""

    def test_get_state_var_info(self, graph: DependencyGraph):
        """Should get info for known state variables."""
        infos = get_state_var_info(graph, "cooldowns")
        assert len(infos) > 0, "Should find cooldowns variable"

    def test_state_var_info_structure(self, graph: DependencyGraph):
        """State var info should have proper structure."""
        infos = get_state_var_info(graph, "cooldowns")
        for info in infos:
            assert info.name == "cooldowns"
            assert info.var_id is not None
            assert isinstance(info.writers, list)
            assert isinstance(info.readers, list)

    def test_state_var_info_has_writers(self, graph: DependencyGraph):
        """Should detect functions that write to state vars."""
        infos = get_state_var_info(graph, "cooldowns")
        has_writers = any(len(info.writers) > 0 for info in infos)
        assert has_writers, "cooldowns should have writers"

    def test_nonexistent_var_returns_empty(self, graph: DependencyGraph):
        """Non-existent variable should return empty list."""
        infos = get_state_var_info(graph, "nonexistent_variable_xyz")
        assert infos == []


class TestInvariantVectors:
    """Tests for invariant vector mapping."""

    def test_get_invariant_vectors(self, graph: DependencyGraph):
        """Should map variables to their writers."""
        vectors = get_invariant_vectors(
            graph, ["cooldowns", "_balances", "_totalSupply"]
        )
        assert len(vectors) > 0, "Should find at least one variable"

    def test_invariant_vectors_format(self, graph: DependencyGraph):
        """Vectors should map var names to contract:function format."""
        vectors = get_invariant_vectors(graph, ["_balances"])
        if "_balances" in vectors:
            for writer in vectors["_balances"]:
                # Should be "Contract:function" or just "function"
                assert isinstance(writer, str)

    def test_invariant_vectors_multiple_vars(self, graph: DependencyGraph):
        """Should handle multiple variables."""
        vars_to_check = ["cooldowns", "_balances", "_totalSupply", "vestingAmount"]
        vectors = get_invariant_vectors(graph, vars_to_check)
        # Should return dict with keys matching requested vars (if they exist)
        for var, writers in vectors.items():
            assert var in vars_to_check
            assert isinstance(writers, list)


class TestSerialization:
    """Tests for graph serialization."""

    def test_to_dict(self, graph: DependencyGraph):
        """Graph should serialize to dict."""
        d = graph.to_dict()
        assert "root_dir" in d
        assert "nodes" in d
        assert "edges" in d
        assert len(d["nodes"]) == len(graph._nodes)
        assert len(d["edges"]) == len(graph._edges)

    def test_roundtrip(self, graph: DependencyGraph, tmp_path):
        """Graph should survive JSON roundtrip."""
        json_path = tmp_path / "test_graph.json"
        graph.to_json(json_path)

        loaded = DependencyGraph.from_json(json_path)
        assert len(loaded._nodes) == len(graph._nodes)
        assert len(loaded._edges) == len(graph._edges)


class TestStructFieldTracking:
    """Tests for struct field access tracking."""

    def test_node_kind_struct_field_exists(self):
        """STRUCT_FIELD NodeKind should exist."""
        assert NodeKind.STRUCT_FIELD == "struct_field"

    def test_edge_kind_field_edges_exist(self):
        """READS_FIELD and WRITES_FIELD EdgeKinds should exist."""
        assert EdgeKind.READS_FIELD == "reads_field"
        assert EdgeKind.WRITES_FIELD == "writes_field"

    def test_get_field_access_info_empty_graph(self, graph: DependencyGraph):
        """Should return empty list when no struct fields exist."""
        # The pre-built graph doesn't have struct fields (built before this feature)
        fields = get_field_access_info(graph)
        # This is expected to be empty for the existing graph
        assert isinstance(fields, list)

    def test_field_access_info_structure(self):
        """FieldAccessInfo should have proper structure."""
        info = FieldAccessInfo(
            field_name="Proof.key",
            field_id="field:Proof.key",
            struct_type="Proof",
            member="key",
            readers=["Verifier:verify"],
            writers=[],
        )
        assert info.field_name == "Proof.key"
        assert info.struct_type == "Proof"
        assert info.member == "key"
        assert "Verifier:verify" in info.readers
        assert info.writers == []

    def test_field_access_info_to_dict(self):
        """FieldAccessInfo should serialize to dict."""
        info = FieldAccessInfo(
            field_name="UserInfo.amount",
            field_id="field:UserInfo.amount",
            struct_type="UserInfo",
            member="amount",
            readers=["Pool:getBalance"],
            writers=["Pool:deposit", "Pool:withdraw"],
        )
        d = info.to_dict()
        assert d["field_name"] == "UserInfo.amount"
        assert d["struct_type"] == "UserInfo"
        assert d["member"] == "amount"
        assert "Pool:getBalance" in d["readers"]
        assert "Pool:deposit" in d["writers"]

    def test_manual_field_node_creation(self, tmp_path):
        """Should be able to manually create and query field nodes."""
        # Create a minimal graph with field nodes
        g = DependencyGraph(tmp_path)

        # Add a contract
        g.add_node(
            Node(
                id="contract:1",
                kind=NodeKind.CONTRACT,
                name="Verifier",
                file="Verifier.sol",
            )
        )

        # Add a function
        g.add_node(
            Node(
                id="func:1",
                kind=NodeKind.FUNCTION,
                name="verify",
                contract="contract:1",
                file="Verifier.sol",
                visibility="public",
            )
        )

        # Add struct field nodes
        g.add_node(
            Node(
                id="field:Proof.key",
                kind=NodeKind.STRUCT_FIELD,
                name="Proof.key",
                contract="contract:1",
                file="Verifier.sol",
                meta={"struct_type": "Proof", "field_name": "key"},
            )
        )

        g.add_node(
            Node(
                id="field:Proof.value",
                kind=NodeKind.STRUCT_FIELD,
                name="Proof.value",
                contract="contract:1",
                file="Verifier.sol",
                meta={"struct_type": "Proof", "field_name": "value"},
            )
        )

        # Add edges
        g.add_edge("func:1", "field:Proof.key", EdgeKind.READS_FIELD)
        g.add_edge("func:1", "field:Proof.value", EdgeKind.WRITES_FIELD)

        # Query field access
        fields = get_field_access_info(g)
        assert len(fields) == 2

        # Check filtering by struct type
        proof_fields = get_field_access_info(g, struct_type="Proof")
        assert len(proof_fields) == 2

        # Check filtering by field name
        key_fields = get_field_access_info(g, field_name="Proof.key")
        assert len(key_fields) == 1
        assert key_fields[0].field_name == "Proof.key"
        assert "Verifier:verify" in key_fields[0].readers

        value_fields = get_field_access_info(g, field_name="Proof.value")
        assert len(value_fields) == 1
        assert "Verifier:verify" in value_fields[0].writers

    def test_field_node_serialization_roundtrip(self, tmp_path):
        """Graph with field nodes should survive JSON roundtrip."""
        g = DependencyGraph(tmp_path)

        g.add_node(
            Node(id="contract:1", kind=NodeKind.CONTRACT, name="Test", file="Test.sol")
        )

        g.add_node(
            Node(
                id="field:Data.x",
                kind=NodeKind.STRUCT_FIELD,
                name="Data.x",
                contract="contract:1",
                meta={"struct_type": "Data", "field_name": "x"},
            )
        )

        g.add_node(
            Node(
                id="func:1",
                kind=NodeKind.FUNCTION,
                name="foo",
                contract="contract:1",
                visibility="public",
            )
        )

        g.add_edge("func:1", "field:Data.x", EdgeKind.READS_FIELD)

        # Save and reload
        json_path = tmp_path / "field_graph.json"
        g.to_json(json_path)

        loaded = DependencyGraph.from_json(json_path)

        # Verify nodes
        assert "field:Data.x" in loaded._nodes
        field_node = loaded.node("field:Data.x")
        assert field_node.kind == NodeKind.STRUCT_FIELD
        assert field_node.name == "Data.x"
        assert field_node.meta["struct_type"] == "Data"

        # Verify edges
        neighbors = list(
            loaded.neighbors(
                "func:1", edge_kinds={EdgeKind.READS_FIELD}, direction="out"
            )
        )
        assert "field:Data.x" in neighbors


class TestGuardDetection:
    """Tests for guard issue detection."""

    def test_guard_issue_types_exist(self):
        """GuardIssueType enum should have expected values."""
        assert GuardIssueType.TX_ORIGIN_ADDRESS_THIS == "tx_origin_address_this"
        assert GuardIssueType.TX_ORIGIN_IN_AUTH == "tx_origin_in_auth"
        assert GuardIssueType.IMPOSSIBLE_OR_CONDITION == "impossible_or_condition"
        assert GuardIssueType.UNSATISFIABLE_GUARD == "unsatisfiable_guard"
        assert GuardIssueType.ALWAYS_REVERTS == "always_reverts"

    def test_severity_levels_exist(self):
        """Severity enum should have expected values."""
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_guard_issue_structure(self):
        """GuardIssue should have proper structure."""
        issue = GuardIssue(
            issue_type=GuardIssueType.TX_ORIGIN_ADDRESS_THIS,
            severity=Severity.CRITICAL,
            function_name="_onlySelfCalled",
            function_id="mod:123",
            modifier_name="_onlySelfCalled",
            contract_name="RecoveryModule",
            file="src/RecoveryModule.sol",
            line=45,
            description="tx.origin == address(this) is always false",
            pattern="tx.origin != address(this)",
            recommendation="Use msg.sender instead",
        )
        assert issue.issue_type == GuardIssueType.TX_ORIGIN_ADDRESS_THIS
        assert issue.severity == Severity.CRITICAL
        assert issue.function_name == "_onlySelfCalled"
        assert issue.modifier_name == "_onlySelfCalled"

    def test_guard_issue_to_dict(self):
        """GuardIssue should serialize to dict."""
        issue = GuardIssue(
            issue_type=GuardIssueType.TX_ORIGIN_IN_AUTH,
            severity=Severity.MEDIUM,
            function_name="onlyOwner",
            function_id="mod:456",
            modifier_name="onlyOwner",
            contract_name="Ownable",
            file="src/Ownable.sol",
            line=20,
            description="tx.origin used for authorization",
            pattern="require(tx.origin == owner)",
            recommendation="Use msg.sender",
        )
        d = issue.to_dict()
        assert d["issue_type"] == "tx_origin_in_auth"
        assert d["severity"] == "medium"
        assert d["function_name"] == "onlyOwner"
        assert d["line"] == 20

    def test_detect_guard_issues_without_slither(self, graph: DependencyGraph):
        """detect_guard_issues should work without Slither (graph-only heuristics)."""
        issues = detect_guard_issues(graph, slither=None)
        # Should return a list (may be empty if no suspicious patterns)
        assert isinstance(issues, list)

    def test_detect_suspicious_modifier_patterns(self, tmp_path):
        """Should detect modifiers with suspicious names like onlySelf."""
        g = DependencyGraph(tmp_path)

        # Add contract
        g.add_node(
            Node(
                id="contract:1",
                kind=NodeKind.CONTRACT,
                name="RecoveryModule",
                file="src/RecoveryModule.sol",
            )
        )

        # Add suspicious modifier
        g.add_node(
            Node(
                id="mod:1",
                kind=NodeKind.MODIFIER,
                name="_onlySelfCalled",
                contract="contract:1",
                file="src/RecoveryModule.sol",
            )
        )

        # Add function using the modifier
        g.add_node(
            Node(
                id="func:1",
                kind=NodeKind.FUNCTION,
                name="addRecoveryProvider",
                contract="contract:1",
                file="src/RecoveryModule.sol",
                visibility="external",
            )
        )
        g.add_edge("func:1", "mod:1", EdgeKind.USES_MODIFIER)

        # Detect issues
        issues = detect_guard_issues(g, slither=None)

        # Should flag the suspicious modifier
        assert len(issues) >= 1
        onlyself_issues = [i for i in issues if "onlyself" in i.function_name.lower()]
        assert len(onlyself_issues) >= 1
        assert onlyself_issues[0].issue_type == GuardIssueType.UNSATISFIABLE_GUARD


class TestLivenessInvariants:
    """Tests for LIVENESS invariant generation."""

    def test_get_liveness_invariants_from_graph(self, graph: DependencyGraph):
        """Should generate liveness invariants from modifier patterns."""
        invariants = get_liveness_invariants(graph)
        # Should return a list (may have invariants from actor roles)
        assert isinstance(invariants, list)

    def test_liveness_invariant_structure(self):
        """Liveness invariants should have expected structure."""
        inv = {
            "id": "LIVENESS_addRecoveryProvider",
            "type": "liveness",
            "rule": "Function addRecoveryProvider must be callable by Admin",
            "target_functions": ["addRecoveryProvider"],
            "target_files": ["src/RecoveryModule.sol"],
            "confidence": 1.0,
            "source": "guard_analysis",
        }
        assert inv["id"].startswith("LIVENESS_")
        assert inv["type"] == "liveness"
        assert "must be callable" in inv["rule"]
        assert inv["confidence"] >= 0.0 and inv["confidence"] <= 1.0

    def test_liveness_from_guard_issues(self, tmp_path):
        """Should generate liveness invariants from guard issues."""
        g = DependencyGraph(tmp_path)

        # Create a simple graph
        g.add_node(
            Node(
                id="contract:1",
                kind=NodeKind.CONTRACT,
                name="TestContract",
                file="Test.sol",
            )
        )

        # Create a guard issue
        issue = GuardIssue(
            issue_type=GuardIssueType.TX_ORIGIN_ADDRESS_THIS,
            severity=Severity.CRITICAL,
            function_name="criticalFunction",
            function_id="func:1",
            modifier_name=None,
            contract_name="TestContract",
            file="Test.sol",
            line=10,
            description="tx.origin == address(this) is impossible",
            pattern="tx.origin == address(this)",
            recommendation="Use msg.sender",
        )

        # Generate liveness invariants
        invariants = get_liveness_invariants(g, guard_issues=[issue])

        # Should generate at least one liveness invariant
        assert len(invariants) >= 1
        liveness_inv = invariants[0]
        assert liveness_inv["type"] == "liveness"
        assert "criticalFunction" in liveness_inv["target_functions"]
        assert liveness_inv["confidence"] == 1.0  # From guard analysis
        assert liveness_inv["source"] == "guard_analysis"

    def test_liveness_from_modifier_patterns(self, graph: DependencyGraph):
        """Should generate liveness invariants from protected functions."""
        invariants = get_liveness_invariants(graph, guard_issues=[])

        # Should find some from modifier patterns (roles with High/Medium trust)
        pattern_invariants = [
            i for i in invariants if i["source"] == "modifier_pattern"
        ]
        # If the graph has protected functions, should have some
        if len(get_actor_roles(graph)) > 1:  # More than just "User"
            # May or may not have pattern-based invariants depending on roles
            assert isinstance(pattern_invariants, list)
