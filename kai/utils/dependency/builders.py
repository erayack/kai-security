"""Builder functions for creating DependencyGraph instances."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .graph import DependencyGraph
from .models import EdgeKind, Node, NodeKind


_IMPORT_RE = re.compile(
    r"""(?xm)
    ^\s*import\s+
    (?:["'](?P<p1>[^"']+)["']|      # import "path";
       \{[^}]*\}\s*from\s*["'](?P<p2>[^"']+)["']|   # import {A} from "path";
       \*\s*as\s+\w+\s*from\s*["'](?P<p3>[^"']+)["'])  # import * as X from "path";
    \s*;
    """
)


def _parse_imports(code: str) -> List[str]:
    """Parse import statements from Solidity code."""
    out: List[str] = []
    for m in _IMPORT_RE.finditer(code or ""):
        p = m.group("p1") or m.group("p2") or m.group("p3")
        if p:
            out.append(p.strip())
    return out


def _resolve_import(
    import_path: str, *, from_file: str, all_files: Set[str]
) -> Optional[str]:
    """Resolve an import path to a file in the project."""
    imp = import_path.replace("\\", "/").strip()
    if imp.startswith((".", "..")):
        base_dir = str(Path(from_file).parent).replace(os.sep, "/")
        norm = str(Path(base_dir, imp)).replace(os.sep, "/")
        norm = str(Path(norm)).replace(os.sep, "/")
        if norm in all_files:
            return norm
        cands = [f for f in all_files if f.endswith(norm)]
        return cands[0] if len(cands) == 1 else None

    # bare import: try exact then suffix match
    if imp in all_files:
        return imp
    cands = [f for f in all_files if f.endswith(imp)]
    if len(cands) == 1:
        return cands[0]

    # common: remapped deps under lib/node_modules; pick shortest suffix match
    if cands:
        cands.sort(key=len)
        return cands[0]
    return None


def _file_rel_for(obj: Any, graph: DependencyGraph) -> Optional[str]:
    """Extract file path from a Slither object."""
    for attr_chain in [
        ("source_mapping", "filename", "absolute"),
        ("source_mapping", "filename", "relative"),
        ("source_mapping", "filename_absolute"),
        ("source_mapping", "filename"),
        ("source_mapping", "filename_short"),
        ("file_scope", "filename", "absolute"),
        ("file_scope", "filename"),
        ("file_scope", "filename_absolute"),
    ]:
        cur = obj
        ok = True
        for a in attr_chain:
            if not hasattr(cur, a):
                ok = False
                break
            cur = getattr(cur, a)
        # handle Slither Filename object if it stringifies to path
        if ok and cur and not isinstance(cur, str) and hasattr(cur, "absolute"):
            cur = str(cur.absolute)

        if ok and isinstance(cur, str) and cur:
            return graph.norm_path(cur)
    return None


def _ensure_ir_analyzed(fnlike: Any) -> None:
    """Ensure IR is generated for a function-like object."""
    try:
        fnlike.generate_slithir_and_analyze()
    except Exception:
        return


def _extract_field_access(
    fnlike: Any,
    graph: DependencyGraph,
    src_nid: str,
    contract_node: str,
) -> None:
    """
    Extract struct field access from function IR and add edges.

    This creates STRUCT_FIELD nodes and READS_FIELD/WRITES_FIELD edges
    for fine-grained tracking of struct member usage.
    """
    # Import Slither IR types
    try:
        from slither.slithir.operations import Member, Index
        from slither.slithir.variables import ReferenceVariable
    except ImportError:
        return

    # Track which ReferenceVariables are written to
    written_refs: Set[int] = set()

    # First pass: identify written reference variables
    for node in getattr(fnlike, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            # Check if this IR writes to a reference variable
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is not None and isinstance(lvalue, ReferenceVariable):
                written_refs.add(id(lvalue))

    # Second pass: extract Member operations
    for node in getattr(fnlike, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if not isinstance(ir, Member):
                continue

            # Get struct type and field name
            var_left = getattr(ir, "variable_left", None)
            var_right = getattr(ir, "variable_right", None)

            if var_left is None or var_right is None:
                continue

            # Get the struct type name
            var_type = getattr(var_left, "type", None)
            if var_type is None:
                continue

            # Handle different type representations
            type_str = str(var_type)
            # Clean up type string (remove "struct " prefix, array suffixes, etc.)
            if type_str.startswith("struct "):
                type_str = type_str[7:]
            # Remove contract prefix if present (e.g., "Contract.StructName" -> "StructName")
            if "." in type_str:
                type_str = type_str.split(".")[-1]
            # Remove array brackets
            type_str = type_str.rstrip("[]")

            field_name = str(var_right)
            if not field_name or not type_str:
                continue

            # Create field node ID
            field_id = f"field:{type_str}.{field_name}"
            field_display = f"{type_str}.{field_name}"

            # Add field node if not exists
            if field_id not in graph._nodes:
                file_rel = (
                    graph._nodes[contract_node].file
                    if contract_node in graph._nodes
                    else None
                )
                graph.add_node(
                    Node(
                        id=field_id,
                        kind=NodeKind.STRUCT_FIELD,
                        name=field_display,
                        contract=contract_node,
                        file=file_rel,
                        meta={
                            "struct_type": type_str,
                            "field_name": field_name,
                        },
                    )
                )

            # Determine if this is a read or write
            # The result of Member is a ReferenceVariable - check if it's written
            lvalue = getattr(ir, "lvalue", None)
            is_write = lvalue is not None and id(lvalue) in written_refs

            if is_write:
                graph.add_edge(src_nid, field_id, EdgeKind.WRITES_FIELD)
            else:
                graph.add_edge(src_nid, field_id, EdgeKind.READS_FIELD)


def _node_id_for_fnlike(
    obj: Any,
    fn_node_by_slither_id: Dict[int, str],
    mod_node_by_slither_id: Dict[int, str],
) -> Optional[str]:
    """Get the graph node ID for a Slither function/modifier object."""
    try:
        oid = int(getattr(obj, "id"))
    except Exception:
        return None
    if oid in fn_node_by_slither_id:
        return fn_node_by_slither_id[oid]
    if oid in mod_node_by_slither_id:
        return mod_node_by_slither_id[oid]
    return None


def build_from_slither(
    project_root: str | Path,
    *,
    slither_kwargs: Optional[Dict[str, Any]] = None,
    include_external_nodes: bool = True,
    build_import_edges: bool = True,
) -> DependencyGraph:
    """
    Build a DependencyGraph from a Solidity project using Slither.

    Args:
        project_root: Path to the project root or a single .sol file
        slither_kwargs: Additional kwargs to pass to Slither constructor
        include_external_nodes: Whether to include external/unresolved nodes
        build_import_edges: Whether to parse and build import edges

    Returns:
        A populated DependencyGraph

    Example:
        g = build_from_slither("/app/master", slither_kwargs={"foundry_compile_all": True})
    """
    project_root = Path(project_root).resolve()
    g = DependencyGraph(project_root)

    # Slither import paths differ across versions
    try:
        from slither import Slither  # type: ignore
    except Exception:
        from slither.slither import Slither  # type: ignore

    sl = Slither(str(project_root), **(slither_kwargs or {}))

    # --- FILE nodes (from slither.source_code)
    source_code: Dict[str, str] = getattr(sl, "source_code", {}) or {}
    for raw_path in source_code.keys():
        rel = g.norm_path(raw_path)
        fid = g.file_id(rel)
        g.add_node(Node(id=fid, kind=NodeKind.FILE, name=Path(rel).name, file=rel))

    # --- IMPORT edges (text-based, robust across tool versions)
    if build_import_edges and source_code:
        all_files = {g.norm_path(p) for p in source_code.keys()}
        for raw_path, code in source_code.items():
            src_rel = g.norm_path(raw_path)
            src_fid = g.file_id(src_rel)
            for imp in _parse_imports(code):
                dst_rel = _resolve_import(imp, from_file=src_rel, all_files=all_files)
                if dst_rel is None:
                    if include_external_nodes:
                        ext_id = f"external:file:{imp}"
                        g.add_node(
                            Node(id=ext_id, kind=NodeKind.EXTERNAL, name=imp, file=None)
                        )
                        g.add_edge(
                            src_fid,
                            ext_id,
                            EdgeKind.IMPORTS,
                            import_path=imp,
                            resolved=False,
                        )
                    continue

                dst_fid = g.file_id(dst_rel)
                if dst_fid not in g._nodes:
                    g.add_node(
                        Node(
                            id=dst_fid,
                            kind=NodeKind.FILE,
                            name=Path(dst_rel).name,
                            file=dst_rel,
                        )
                    )
                g.add_edge(
                    src_fid, dst_fid, EdgeKind.IMPORTS, import_path=imp, resolved=True
                )

    # --- Build contract/function/var/event nodes
    contract_node_by_slither_id: Dict[int, str] = {}
    fn_node_by_slither_id: Dict[int, str] = {}
    mod_node_by_slither_id: Dict[int, str] = {}
    var_node_by_canonical: Dict[str, str] = {}
    event_node_by_canonical: Dict[str, str] = {}
    library_contracts: Set[str] = set()  # Track which contracts are libraries

    # Contracts
    for c in getattr(sl, "contracts", []) or []:
        if getattr(c, "id") is None:
            continue
        cid = int(getattr(c, "id"))
        c_node = f"contract:{cid}"
        contract_node_by_slither_id[cid] = c_node

        file_rel = _file_rel_for(c, g)
        g.add_node(
            Node(
                id=c_node,
                kind=NodeKind.CONTRACT,
                name=str(getattr(c, "name")),
                file=file_rel,
                meta={
                    "is_interface": bool(getattr(c, "is_interface", False)),
                    "is_library": bool(getattr(c, "is_library", False)),
                    "is_abstract": bool(getattr(c, "is_abstract", False)),
                },
            )
        )

        if file_rel:
            fid = g.file_id(file_rel)
            if fid not in g._nodes:
                g.add_node(
                    Node(
                        id=fid,
                        kind=NodeKind.FILE,
                        name=Path(file_rel).name,
                        file=file_rel,
                    )
                )
            g.add_edge(fid, c_node, EdgeKind.DEFINES)

    # Inheritance edges
    for c in getattr(sl, "contracts", []) or []:
        if getattr(c, "id") is None:
            continue
        cid = int(getattr(c, "id"))
        c_node = contract_node_by_slither_id[cid]
        bases = (
            getattr(c, "immediate_inheritance", None)
            or getattr(c, "inheritance", None)
            or []
        )
        for b in bases:
            if getattr(b, "id") is None:
                continue
            bid = int(getattr(b, "id"))
            b_node = contract_node_by_slither_id.get(bid)
            if b_node:
                g.add_edge(c_node, b_node, EdgeKind.INHERITS)

    # State variables (declared)
    for c in getattr(sl, "contracts", []) or []:
        if getattr(c, "id") is None:
            continue
        cid = int(getattr(c, "id"))
        c_node = contract_node_by_slither_id[cid]
        vars_decl = (
            getattr(c, "state_variables_declared", None)
            or getattr(c, "state_variables", None)
            or []
        )
        for v in vars_decl:
            v_name = str(getattr(v, "name", ""))
            v_can = str(getattr(v, "canonical_name", "")) or f"{cid}.{v_name}"
            v_node = var_node_by_canonical.get(v_can)
            if not v_node:
                v_node = f"statevar:{v_can}"
                var_node_by_canonical[v_can] = v_node
                g.add_node(
                    Node(
                        id=v_node,
                        kind=NodeKind.STATE_VAR,
                        name=v_name or v_can,
                        contract=c_node,
                        file=_file_rel_for(v, g) or g._nodes[c_node].file,
                        meta={
                            "type": str(
                                getattr(
                                    getattr(v, "type", None),
                                    "type",
                                    getattr(v, "type", ""),
                                )
                            ),
                            "canonical_name": v_can,
                            "visibility": str(getattr(v, "visibility", "")) or None,
                        },
                    )
                )
            g.add_edge(c_node, v_node, EdgeKind.DECLARES_STATEVAR)

    # Events (declared)
    for c in getattr(sl, "contracts", []) or []:
        if getattr(c, "id") is None:
            continue
        cid = int(getattr(c, "id"))
        c_node = contract_node_by_slither_id[cid]

        # Track if this is a library contract
        if g._nodes[c_node].meta.get("is_library", False):
            library_contracts.add(c_node)

        events = getattr(c, "events_declared", None) or getattr(c, "events", None) or []
        for evt in events:
            evt_name = str(getattr(evt, "name", ""))
            evt_can = str(getattr(evt, "canonical_name", "")) or f"{cid}.{evt_name}"

            if evt_can in event_node_by_canonical:
                continue

            evt_node = f"event:{evt_can}"
            event_node_by_canonical[evt_can] = evt_node

            # Extract indexed parameters
            indexed_params: List[str] = []
            for param in getattr(evt, "elems", []) or []:
                if getattr(param, "indexed", False):
                    indexed_params.append(str(getattr(param, "name", "")))

            file_rel = _file_rel_for(evt, g) or g._nodes[c_node].file
            g.add_node(
                Node(
                    id=evt_node,
                    kind=NodeKind.EVENT,
                    name=evt_name or evt_can,
                    contract=c_node,
                    file=file_rel,
                    signature=str(getattr(evt, "full_name", "")) or None,
                    meta={
                        "canonical_name": evt_can,
                        "indexed_params": indexed_params,
                    },
                )
            )
            g.add_edge(c_node, evt_node, EdgeKind.DECLARES_EVENT)

    # Using directives (using X for Y) -> USES_LIBRARY
    for c in getattr(sl, "contracts", []) or []:
        if getattr(c, "id") is None:
            continue
        cid = int(getattr(c, "id"))
        c_node = contract_node_by_slither_id[cid]

        # Slither stores using directives in different ways depending on version
        using_for = getattr(c, "using_for", None) or {}
        if isinstance(using_for, dict):
            for target_type, libraries in using_for.items():
                libs = libraries if isinstance(libraries, list) else [libraries]
                for lib in libs:
                    lib_contract = getattr(lib, "contract", lib)
                    try:
                        lib_cid = int(getattr(lib_contract, "id"))
                        lib_node = contract_node_by_slither_id.get(lib_cid)
                    except Exception:
                        lib_node = None

                    if lib_node:
                        g.add_edge(
                            c_node,
                            lib_node,
                            EdgeKind.USES_LIBRARY,
                            target_type=str(target_type),
                        )

    # Functions + Modifiers (declared)
    for c in getattr(sl, "contracts", []) or []:
        if getattr(c, "id") is None:
            continue
        cid = int(getattr(c, "id"))
        c_node = contract_node_by_slither_id[cid]

        fns = (
            getattr(c, "functions_declared", None)
            or getattr(c, "functions", None)
            or []
        )
        for f in fns:
            if getattr(f, "id") is None:
                continue
            fid_int = int(getattr(f, "id"))
            fn_node = f"func:{fid_int}"
            fn_node_by_slither_id[fid_int] = fn_node

            vis = getattr(f, "visibility", None)
            sig = (
                getattr(f, "signature_str", None)
                or getattr(f, "full_name", None)
                or getattr(f, "canonical_name", None)
            )
            file_rel = _file_rel_for(f, g) or g._nodes[c_node].file

            g.add_node(
                Node(
                    id=fn_node,
                    kind=NodeKind.FUNCTION,
                    name=str(getattr(f, "name")),
                    contract=c_node,
                    file=file_rel,
                    signature=str(sig) if sig else None,
                    visibility=str(vis) if vis else None,
                    meta={
                        "canonical_name": str(getattr(f, "canonical_name", "")) or None,
                        "payable": bool(getattr(f, "payable", False)),
                        "view": bool(getattr(f, "view", False)),
                        "pure": bool(getattr(f, "pure", False)),
                        "is_constructor": bool(getattr(f, "is_constructor", False)),
                        "is_fallback": bool(getattr(f, "is_fallback", False)),
                        "is_receive": bool(getattr(f, "is_receive", False)),
                        "contains_assembly": bool(
                            getattr(f, "contains_assembly", False)
                        ),
                    },
                )
            )
            g.add_edge(c_node, fn_node, EdgeKind.DECLARES_FUNCTION)

        mods = (
            getattr(c, "modifiers_declared", None)
            or getattr(c, "modifiers", None)
            or []
        )
        for m in mods:
            if getattr(m, "id") is None:
                continue
            mid_int = int(getattr(m, "id"))
            mod_node = f"mod:{mid_int}"
            mod_node_by_slither_id[mid_int] = mod_node

            sig = (
                getattr(m, "signature_str", None)
                or getattr(m, "full_name", None)
                or getattr(m, "canonical_name", None)
            )
            file_rel = _file_rel_for(m, g) or g._nodes[c_node].file

            g.add_node(
                Node(
                    id=mod_node,
                    kind=NodeKind.MODIFIER,
                    name=str(getattr(m, "name")),
                    contract=c_node,
                    file=file_rel,
                    signature=str(sig) if sig else None,
                    visibility="modifier",
                    meta={
                        "canonical_name": str(getattr(m, "canonical_name", "")) or None
                    },
                )
            )
            g.add_edge(c_node, mod_node, EdgeKind.DECLARES_MODIFIER)

    # Reads/Writes + Calls + Uses modifiers + Field access
    for c in getattr(sl, "contracts", []) or []:
        cid = int(getattr(c, "id")) if getattr(c, "id") is not None else None
        c_node = contract_node_by_slither_id.get(cid) if cid else None

        fns = (getattr(c, "functions_declared", None) or []) + (
            getattr(c, "modifiers_declared", None) or []
        )
        for fnlike in fns:
            src_nid = _node_id_for_fnlike(
                fnlike, fn_node_by_slither_id, mod_node_by_slither_id
            )
            if not src_nid:
                continue

            _ensure_ir_analyzed(fnlike)

            # Extract struct field access
            if c_node:
                _extract_field_access(fnlike, g, src_nid, c_node)

            # modifiers used by functions
            if getattr(fnlike, "modifiers", None):
                for m in fnlike.modifiers:
                    try:
                        mid = int(getattr(m, "id"))
                    except Exception:
                        continue
                    dst = mod_node_by_slither_id.get(mid)
                    if dst:
                        g.add_edge(src_nid, dst, EdgeKind.USES_MODIFIER)

            # state var deps
            for v in getattr(fnlike, "state_variables_read", []) or []:
                v_can = str(getattr(v, "canonical_name", "")) or str(
                    getattr(v, "name", "")
                )
                v_node = var_node_by_canonical.get(v_can)
                if v_node:
                    g.add_edge(src_nid, v_node, EdgeKind.READS)

            for v in getattr(fnlike, "state_variables_written", []) or []:
                v_can = str(getattr(v, "canonical_name", "")) or str(
                    getattr(v, "name", "")
                )
                v_node = var_node_by_canonical.get(v_can)
                if v_node:
                    g.add_edge(src_nid, v_node, EdgeKind.WRITES)

            # internal calls -> CALLS or LIBRARY_CALL
            for ir in getattr(fnlike, "internal_calls", []) or []:
                callee = getattr(ir, "function", None)
                if callee is None:
                    continue
                dst_nid = _node_id_for_fnlike(
                    callee, fn_node_by_slither_id, mod_node_by_slither_id
                )
                if dst_nid:
                    # Check if this is a library call
                    callee_contract = (
                        g._nodes[dst_nid].contract if dst_nid in g._nodes else None
                    )
                    is_library_call = callee_contract in library_contracts

                    if is_library_call:
                        g.add_edge(
                            src_nid,
                            dst_nid,
                            EdgeKind.LIBRARY_CALL,
                            call_type="internal",
                        )
                    else:
                        g.add_edge(
                            src_nid, dst_nid, EdgeKind.CALLS, call_type="internal"
                        )

            # high level calls (external-ish) -> CALLS, HIGH_LEVEL_CALL, or LIBRARY_CALL
            for target_contract, call in getattr(fnlike, "high_level_calls", []) or []:
                fn_obj = getattr(call, "function", None)
                dst_nid = (
                    _node_id_for_fnlike(
                        fn_obj, fn_node_by_slither_id, mod_node_by_slither_id
                    )
                    if fn_obj is not None
                    else None
                )

                # Check if target is a library
                try:
                    tcid = int(getattr(target_contract, "id"))
                    tc_node = contract_node_by_slither_id.get(tcid)
                except Exception:
                    tc_node = None

                is_library_call = tc_node in library_contracts

                if dst_nid:
                    if is_library_call:
                        g.add_edge(
                            src_nid,
                            dst_nid,
                            EdgeKind.LIBRARY_CALL,
                            call_type="high_level_resolved",
                        )
                    else:
                        g.add_edge(
                            src_nid,
                            dst_nid,
                            EdgeKind.CALLS,
                            call_type="high_level_resolved",
                        )
                else:
                    if tc_node:
                        edge_kind = (
                            EdgeKind.LIBRARY_CALL
                            if is_library_call
                            else EdgeKind.HIGH_LEVEL_CALL
                        )
                        g.add_edge(
                            src_nid,
                            tc_node,
                            edge_kind,
                            function_name=str(getattr(call, "function_name", "")),
                            type_call=str(getattr(call, "type_call", "")),
                            can_send_eth=bool(
                                getattr(call, "can_send_eth", lambda: False)()
                            ),
                        )
                    elif include_external_nodes:
                        ext = f"external:call:{str(getattr(call, 'function_name', ''))}"
                        g.add_node(Node(id=ext, kind=NodeKind.EXTERNAL, name=ext))
                        g.add_edge(src_nid, ext, EdgeKind.HIGH_LEVEL_CALL)

            # library calls via Slither's library_calls attribute
            for lib_call in getattr(fnlike, "library_calls", []) or []:
                lib_contract, lib_fn = (
                    lib_call
                    if isinstance(lib_call, tuple) and len(lib_call) == 2
                    else (None, lib_call)
                )
                if lib_fn is None:
                    continue
                dst_nid = _node_id_for_fnlike(
                    lib_fn, fn_node_by_slither_id, mod_node_by_slither_id
                )
                if dst_nid:
                    g.add_edge(
                        src_nid, dst_nid, EdgeKind.LIBRARY_CALL, call_type="library"
                    )

            # low level calls (call/delegatecall/etc) -> external node
            for ll in getattr(fnlike, "low_level_calls", []) or []:
                if not include_external_nodes:
                    continue
                ext = f"external:low_level:{str(getattr(ll, 'function_name', 'call'))}"
                if ext not in g._nodes:
                    g.add_node(Node(id=ext, kind=NodeKind.EXTERNAL, name=ext))
                g.add_edge(src_nid, ext, EdgeKind.LOW_LEVEL_CALL)

            # Event emissions -> EMITS
            # Try IR-level first for accuracy
            emitted_events: Set[str] = set()
            for node in getattr(fnlike, "nodes", []) or []:
                for ir in getattr(node, "irs", []) or []:
                    # Look for EventCall in SlithIR
                    ir_type = type(ir).__name__
                    if ir_type == "EventCall":
                        evt_name = str(getattr(ir, "name", ""))
                        if evt_name:
                            emitted_events.add(evt_name)

            # Fallback: use Slither's events_emitted if available
            if not emitted_events:
                for evt in getattr(fnlike, "events_emitted", []) or []:
                    evt_name = str(getattr(evt, "name", ""))
                    if evt_name:
                        emitted_events.add(evt_name)

            # Add EMITS edges
            for evt_name in emitted_events:
                # Find matching event node
                for evt_can, evt_nid in event_node_by_canonical.items():
                    if evt_can.endswith(f".{evt_name}") or evt_name == evt_can:
                        g.add_edge(src_nid, evt_nid, EdgeKind.EMITS)
                        break

    return g
