"""
Solidity builder - constructs DependencyGraph from Slither analysis.
"""

from __future__ import annotations

import re
import os
import stat
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import BaseBuilder
from ..graph import DependencyGraph
from ..models import EdgeKind, Node, NodeKind, SourceSpan


_IMPORT_RE = re.compile(
    r"""(?xm)
    ^\s*import\s+
    (?:["'](?P<p1>[^"']+)["']|
       \{[^}]*\}\s*from\s*["'](?P<p2>[^"']+)["']|
       \*\s*as\s+\w+\s*from\s*["'](?P<p3>[^"']+)["'])
    \s*;
    """
)


class SolidityBuilder(BaseBuilder):
    """Build DependencyGraph from Solidity projects using Slither."""

    @property
    def language(self) -> str:
        return "solidity"

    def _ensure_writable_path(self, path: Path) -> None:
        """
        Best-effort: ensure a file/dir under the target project is writable.

        Some fixture repos may ship with read-only cached artifacts (e.g., crytic-compile's
        `forge-cache/solidity-files-cache.json`). That breaks Slither compilation with:
          Permission denied (os error 13)
        """
        try:
            if not path.exists():
                return

            # If it's writable already, nothing to do.
            if os.access(path, os.W_OK):
                return

            if path.is_file():
                # Prefer deleting stale cache files (safer than chmod across platforms).
                try:
                    path.unlink()
                    return
                except Exception:
                    # Fall back to chmod.
                    try:
                        path.chmod(0o600)
                        return
                    except Exception:
                        return

            if path.is_dir():
                try:
                    mode = path.stat().st_mode
                    path.chmod(mode | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRUSR)
                except Exception:
                    return
        except Exception:
            return

    def _ensure_writable_dir(self, path: Path) -> None:
        """
        Ensure `path` is a writable directory.

        If a fixture shipped with read-only build artifacts (or even a file at that location),
        we remove them and recreate the directory to allow Foundry/Crytic-compile to run.
        """
        try:
            if path.exists() and not path.is_dir():
                try:
                    path.unlink()
                except Exception:
                    return

            path.mkdir(parents=True, exist_ok=True)
            self._ensure_writable_path(path)

            # Verify we can actually write inside.
            probe = path / ".kai_write_probe"
            try:
                probe.write_text("ok", encoding="utf-8")
                probe.unlink()
                return
            except Exception:
                pass

            # Last resort: remove and recreate (build outputs are safe to blow away).
            try:
                shutil.rmtree(path, ignore_errors=True)
                path.mkdir(parents=True, exist_ok=True)
                probe.write_text("ok", encoding="utf-8")
                probe.unlink()
            except Exception:
                return
        except Exception:
            return

    def _prepare_foundry_compile_dirs(self, project_root: Path) -> None:
        """
        Ensure Foundry/Crytic-compile working dirs exist and are writable.

        This is intentionally conservative and local to the project root.
        """
        # Some fixtures are checked out with a read-only project root (0555), which makes
        # Foundry unable to create/update `cache/` and to rotate `out/` artifacts.
        # If we own the directory, best-effort add owner write permission.
        try:
            self._ensure_writable_path(project_root)
        except Exception:
            pass

        # Common output/cache locations used by foundry & crytic-compile.
        out_dir = project_root / "out"
        cache_dir = project_root / "cache"
        forge_cache_dir = project_root / "forge-cache"

        # If the repo shipped with read-only artifacts under out/, Foundry may fail even
        # though the directory itself is writable (because it tries to overwrite them).
        # Since these are build outputs, it is safe to wipe them.
        try:
            if out_dir.exists():
                shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass

        # Ensure directories are writable (and recreate if needed).
        for d in [out_dir, cache_dir, forge_cache_dir]:
            self._ensure_writable_dir(d)

        # Force build-info to be writable specifically (crytic-compile parses it).
        self._ensure_writable_dir(out_dir / "build-info")

        # Known problematic cache file in our fixture runs.
        self._ensure_writable_path(project_root / "forge-cache" / "solidity-files-cache.json")

    def _default_foundry_toml(self, project_root: Path) -> str:
        """
        Generate a minimal Foundry config for projects that don't ship a root `foundry.toml`.

        Crytic-compile's Foundry platform *requires* `foundry.toml` to detect the project root.
        Some repos compile fine with `forge --root ...` and no config file; for those, we
        synthesize a minimal config just for Slither's compilation step, then delete it.
        """
        # Heuristic: Foundry defaults to `src/`, but many repos use `contracts/`.
        if (project_root / "contracts").is_dir():
            src = "contracts"
        elif (project_root / "src").is_dir():
            src = "src"
        else:
            # Last resort: keep Foundry defaults.
            src = "src"

        libs: List[str] = []
        if (project_root / "lib").is_dir():
            libs.append("lib")

        remappings: List[str] = []
        # Common Foundry install for OpenZeppelin. Some repos import using NPM-style
        # "@openzeppelin/..." but `forge config` may not emit the leading "@" remapping.
        # Provide it explicitly so compilation works under crytic-compile.
        if (project_root / "lib" / "openzeppelin-contracts").is_dir():
            remappings.append("@openzeppelin/=lib/openzeppelin-contracts/")

        libs_value = ", ".join(f'"{x}"' for x in libs)
        remappings_value = ", ".join(f'"{x}"' for x in remappings)
        return (
            "[profile.default]\n"
            f'src = "{src}"\n'
            'out = "out"\n'
            f"libs = [{libs_value}]\n"
            f"remappings = [{remappings_value}]\n"
        )

    def build(
        self,
        source: str | Path,
        **kwargs,
    ) -> DependencyGraph:
        """
        Build graph from a Solidity project.

        Args:
            source: Path to project root or single .sol file
            slither_kwargs: Additional kwargs for Slither
            include_external: Include unresolved external nodes
            build_imports: Parse and build import edges
        """
        slither_kwargs: Optional[Dict[str, Any]] = kwargs.get("slither_kwargs")
        include_external: bool = kwargs.get("include_external", True)
        build_imports: bool = kwargs.get("build_imports", True)
        project_root = Path(source).resolve()
        graph = DependencyGraph(project_root)

        # Import Slither
        try:
            from slither import Slither
        except ImportError:
            from slither.slither import Slither

        # Slither passes kwargs through to crytic-compile. If we force the Foundry framework,
        # crytic-compile requires a `foundry.toml` at the project root to identify it as
        # a Foundry project. Some targets (including our BBP fixture) don't have one.
        # In that case, synthesize a minimal config temporarily so Slither can run.
        tmp_foundry_toml: Optional[Path] = None
        try:
            fw = str((slither_kwargs or {}).get("compile_force_framework") or "").lower()
            if fw == "foundry":
                self._prepare_foundry_compile_dirs(project_root)

            try:
                sl = Slither(str(project_root), **(slither_kwargs or {}))
            except AssertionError:
                foundry_toml = project_root / "foundry.toml"
                if fw == "foundry" and not foundry_toml.is_file():
                    tmp_foundry_toml = foundry_toml
                    tmp_foundry_toml.write_text(
                        self._default_foundry_toml(project_root), encoding="utf-8"
                    )
                    sl = Slither(str(project_root), **(slither_kwargs or {}))
                else:
                    raise
        finally:
            if tmp_foundry_toml is not None:
                try:
                    tmp_foundry_toml.unlink()
                except Exception:
                    pass

        # Tracking maps
        self._contract_map: Dict[int, str] = {}
        self._func_map: Dict[int, str] = {}
        self._mod_map: Dict[int, str] = {}
        self._var_map: Dict[str, str] = {}
        self._type_map: Dict[str, str] = {}
        self._event_map: Dict[str, str] = {}
        self._libraries: Set[str] = set()

        # Build phases
        self._build_files(graph, sl)
        if build_imports:
            self._build_imports(graph, sl, include_external)
        self._build_containers(graph, sl)
        self._build_inheritance(graph, sl)
        self._build_types(graph, sl)
        self._build_variables(graph, sl)
        self._build_events(graph, sl)
        self._build_units(graph, sl)
        self._build_interfaces(graph, sl)
        self._build_edges(graph, sl, include_external)

        return graph

    def extract_span(self, obj: Any) -> Optional[SourceSpan]:
        """Extract SourceSpan from Slither object."""
        sm = getattr(obj, "source_mapping", None)
        if sm is None:
            return None

        # Get file path
        filename = None
        for attr in ["filename", "filename_absolute", "filename_relative"]:
            f = getattr(sm, attr, None)
            if f:
                filename = str(
                    getattr(f, "absolute", f) if hasattr(f, "absolute") else f
                )
                break

        if not filename:
            return None

        start_line = (
            getattr(sm, "lines", [None])[0] if getattr(sm, "lines", None) else None
        )
        end_line = (
            getattr(sm, "lines", [None])[-1]
            if getattr(sm, "lines", None)
            else start_line
        )
        start_col = getattr(sm, "starting_column", None)
        end_col = getattr(sm, "ending_column", None)

        if start_line is None:
            return None

        return SourceSpan(
            file=filename,
            start_line=start_line,
            end_line=end_line or start_line,
            start_col=start_col,
            end_col=end_col,
        )

    # --- Build phases ---

    def _build_files(self, g: DependencyGraph, sl: Any) -> None:
        """Create FILE nodes from source_code."""
        source_code = getattr(sl, "source_code", {}) or {}
        for raw_path in source_code.keys():
            rel = g.norm_path(raw_path)
            fid = g.file_id(rel)
            g.add_node(
                Node(
                    id=fid,
                    kind=NodeKind.FILE,
                    name=Path(rel).name,
                    span=SourceSpan(file=rel, start_line=1, end_line=1),
                )
            )

    def _build_imports(
        self, g: DependencyGraph, sl: Any, include_external: bool
    ) -> None:
        """Build IMPORTS edges from parsed import statements."""
        source_code = getattr(sl, "source_code", {}) or {}
        all_files = {g.norm_path(p) for p in source_code.keys()}

        for raw_path, code in source_code.items():
            src_rel = g.norm_path(raw_path)
            src_fid = g.file_id(src_rel)

            for imp in self._parse_imports(code):
                dst_rel = self._resolve_import(imp, src_rel, all_files)

                if dst_rel is None:
                    if include_external:
                        ext_id = f"external:file:{imp}"
                        g.add_node(Node(id=ext_id, kind=NodeKind.EXTERNAL, name=imp))
                        g.add_edge(src_fid, ext_id, EdgeKind.IMPORTS)
                    continue

                dst_fid = g.file_id(dst_rel)
                if dst_fid not in g._nodes:
                    g.add_node(
                        Node(
                            id=dst_fid,
                            kind=NodeKind.FILE,
                            name=Path(dst_rel).name,
                            span=SourceSpan(file=dst_rel, start_line=1, end_line=1),
                        )
                    )
                g.add_edge(src_fid, dst_fid, EdgeKind.IMPORTS)

    def _build_containers(self, g: DependencyGraph, sl: Any) -> None:
        """Create CONTAINER nodes for contracts/interfaces/libraries."""
        for c in getattr(sl, "contracts", []) or []:
            cid = getattr(c, "id", None)
            if cid is None:
                continue
            cid = int(cid)
            node_id = f"container:{cid}"
            self._contract_map[cid] = node_id

            is_lib = bool(getattr(c, "is_library", False))
            if is_lib:
                self._libraries.add(node_id)

            span = self.extract_span(c)
            file_rel = g.norm_path(span.file) if span else None

            g.add_node(
                Node(
                    id=node_id,
                    kind=NodeKind.CONTAINER,
                    name=str(getattr(c, "name")),
                    span=span,
                    meta={
                        "subkind": "library"
                        if is_lib
                        else "interface"
                        if getattr(c, "is_interface", False)
                        else "abstract"
                        if getattr(c, "is_abstract", False)
                        else "contract",
                    },
                )
            )

            # FILE -> CONTAINER (DEFINES)
            if file_rel:
                fid = g.file_id(file_rel)
                if fid in g._nodes:
                    g.add_edge(fid, node_id, EdgeKind.DEFINES)

    def _build_inheritance(self, g: DependencyGraph, sl: Any) -> None:
        """Build INHERITS edges between containers."""
        for c in getattr(sl, "contracts", []) or []:
            cid = getattr(c, "id", None)
            if cid is None:
                continue
            c_node = self._contract_map[int(cid)]

            bases = (
                getattr(c, "immediate_inheritance", None)
                or getattr(c, "inheritance", None)
                or []
            )
            for b in bases:
                bid = getattr(b, "id", None)
                if bid is None:
                    continue
                b_node = self._contract_map.get(int(bid))
                if b_node:
                    g.add_edge(c_node, b_node, EdgeKind.INHERITS)

    def _build_types(self, g: DependencyGraph, sl: Any) -> None:
        """Create TYPE_DEF nodes for structs and enums."""
        for c in getattr(sl, "contracts", []) or []:
            cid = getattr(c, "id", None)
            if cid is None:
                continue
            c_node = self._contract_map[int(cid)]

            # Structs
            for s in (
                getattr(c, "structures_declared", [])
                or getattr(c, "structures", [])
                or []
            ):
                s_name = str(getattr(s, "name", ""))
                s_can = str(getattr(s, "canonical_name", "")) or f"{cid}.{s_name}"

                if s_can in self._type_map:
                    continue

                node_id = f"type:{s_can}"
                self._type_map[s_can] = node_id

                # Extract fields
                fields = []
                for elem in (
                    getattr(s, "elems", {}).values()
                    if isinstance(getattr(s, "elems", None), dict)
                    else []
                ):
                    fields.append(
                        {
                            "name": str(getattr(elem, "name", "")),
                            "type": str(getattr(elem, "type", "")),
                        }
                    )

                span = self.extract_span(s)
                g.add_node(
                    Node(
                        id=node_id,
                        kind=NodeKind.TYPE_DEF,
                        name=s_name,
                        span=span,
                        parent_id=c_node,
                        meta={"subkind": "struct", "fields": fields},
                    )
                )
                g.add_edge(c_node, node_id, EdgeKind.DEFINES)

            # Enums
            for e in getattr(c, "enums_declared", []) or getattr(c, "enums", []) or []:
                e_name = str(getattr(e, "name", ""))
                e_can = str(getattr(e, "canonical_name", "")) or f"{cid}.{e_name}"

                if e_can in self._type_map:
                    continue

                node_id = f"type:{e_can}"
                self._type_map[e_can] = node_id

                values = [str(v) for v in getattr(e, "values", []) or []]

                span = self.extract_span(e)
                g.add_node(
                    Node(
                        id=node_id,
                        kind=NodeKind.TYPE_DEF,
                        name=e_name,
                        span=span,
                        parent_id=c_node,
                        meta={"subkind": "enum", "values": values},
                    )
                )
                g.add_edge(c_node, node_id, EdgeKind.DEFINES)

    def _build_variables(self, g: DependencyGraph, sl: Any) -> None:
        """Create VARIABLE nodes for state variables."""
        for c in getattr(sl, "contracts", []) or []:
            cid = getattr(c, "id", None)
            if cid is None:
                continue
            c_node = self._contract_map[int(cid)]

            vars_decl = (
                getattr(c, "state_variables_declared", None)
                or getattr(c, "state_variables", None)
                or []
            )
            for v in vars_decl:
                v_name = str(getattr(v, "name", ""))
                v_can = str(getattr(v, "canonical_name", "")) or f"{cid}.{v_name}"

                if v_can in self._var_map:
                    continue

                node_id = f"var:{v_can}"
                self._var_map[v_can] = node_id

                v_type = str(
                    getattr(getattr(v, "type", None), "type", getattr(v, "type", ""))
                )
                span = self.extract_span(v)

                g.add_node(
                    Node(
                        id=node_id,
                        kind=NodeKind.VARIABLE,
                        name=v_name,
                        span=span,
                        parent_id=c_node,
                        meta={
                            "type": v_type,
                            "visibility": str(getattr(v, "visibility", "")) or None,
                        },
                    )
                )
                g.add_edge(c_node, node_id, EdgeKind.DEFINES)

    def _build_events(self, g: DependencyGraph, sl: Any) -> None:
        """Create EVENT nodes."""
        for c in getattr(sl, "contracts", []) or []:
            cid = getattr(c, "id", None)
            if cid is None:
                continue
            c_node = self._contract_map[int(cid)]

            events = (
                getattr(c, "events_declared", None) or getattr(c, "events", None) or []
            )
            for evt in events:
                evt_name = str(getattr(evt, "name", ""))
                evt_can = str(getattr(evt, "canonical_name", "")) or f"{cid}.{evt_name}"

                if evt_can in self._event_map:
                    continue

                node_id = f"event:{evt_can}"
                self._event_map[evt_can] = node_id

                indexed = [
                    str(getattr(p, "name", ""))
                    for p in getattr(evt, "elems", []) or []
                    if getattr(p, "indexed", False)
                ]
                span = self.extract_span(evt)

                g.add_node(
                    Node(
                        id=node_id,
                        kind=NodeKind.EVENT,
                        name=evt_name,
                        span=span,
                        parent_id=c_node,
                        meta={
                            "signature": str(getattr(evt, "full_name", "")) or None,
                            "indexed_params": indexed,
                        },
                    )
                )
                g.add_edge(c_node, node_id, EdgeKind.DEFINES)

    def _build_units(self, g: DependencyGraph, sl: Any) -> None:
        """Create UNIT nodes for functions."""
        for c in getattr(sl, "contracts", []) or []:
            cid = getattr(c, "id", None)
            if cid is None:
                continue
            c_node = self._contract_map[int(cid)]

            fns = (
                getattr(c, "functions_declared", None)
                or getattr(c, "functions", None)
                or []
            )
            for f in fns:
                fid = getattr(f, "id", None)
                if fid is None:
                    continue
                fid = int(fid)
                node_id = f"unit:{fid}"
                self._func_map[fid] = node_id

                sig = (
                    getattr(f, "signature_str", None)
                    or getattr(f, "full_name", None)
                    or getattr(f, "canonical_name", None)
                )
                span = self.extract_span(f)

                # Collect type usage from parameters/returns
                type_refs = self._extract_type_refs(f)

                g.add_node(
                    Node(
                        id=node_id,
                        kind=NodeKind.UNIT,
                        name=str(getattr(f, "name")),
                        span=span,
                        parent_id=c_node,
                        meta={
                            "signature": str(sig) if sig else None,
                            "visibility": str(getattr(f, "visibility", "")) or None,
                            "payable": bool(getattr(f, "payable", False)),
                            "view": bool(getattr(f, "view", False)),
                            "pure": bool(getattr(f, "pure", False)),
                            "is_constructor": bool(getattr(f, "is_constructor", False)),
                            "is_fallback": bool(getattr(f, "is_fallback", False)),
                            "is_receive": bool(getattr(f, "is_receive", False)),
                            "type_refs": type_refs,
                        },
                    )
                )
                g.add_edge(c_node, node_id, EdgeKind.DEFINES)

    def _build_interfaces(self, g: DependencyGraph, sl: Any) -> None:
        """Create INTERFACE nodes for modifiers."""
        for c in getattr(sl, "contracts", []) or []:
            cid = getattr(c, "id", None)
            if cid is None:
                continue
            c_node = self._contract_map[int(cid)]

            mods = (
                getattr(c, "modifiers_declared", None)
                or getattr(c, "modifiers", None)
                or []
            )
            for m in mods:
                mid = getattr(m, "id", None)
                if mid is None:
                    continue
                mid = int(mid)
                node_id = f"interface:{mid}"
                self._mod_map[mid] = node_id

                sig = getattr(m, "signature_str", None) or getattr(m, "full_name", None)
                span = self.extract_span(m)

                g.add_node(
                    Node(
                        id=node_id,
                        kind=NodeKind.INTERFACE,
                        name=str(getattr(m, "name")),
                        span=span,
                        parent_id=c_node,
                        meta={
                            "signature": str(sig) if sig else None,
                            "subkind": "modifier",
                        },
                    )
                )
                g.add_edge(c_node, node_id, EdgeKind.DEFINES)

    def _build_edges(self, g: DependencyGraph, sl: Any, include_external: bool) -> None:
        """Build behavioral edges: CALLS, ACCEPTS, READS, WRITES, EMITS, USES_TYPE."""
        for c in getattr(sl, "contracts", []) or []:
            cid = getattr(c, "id", None)
            if cid is None:
                continue

            # Process both functions and modifiers
            fns = (getattr(c, "functions_declared", None) or []) + (
                getattr(c, "modifiers_declared", None) or []
            )

            for fnlike in fns:
                src_id = self._get_unit_id(fnlike)
                if not src_id:
                    continue

                self._ensure_ir(fnlike)

                # ACCEPTS (modifier usage)
                for m in getattr(fnlike, "modifiers", []) or []:
                    mid = getattr(m, "id", None)
                    if mid is None:
                        continue
                    dst = self._mod_map.get(int(mid))
                    if dst:
                        g.add_edge(src_id, dst, EdgeKind.ACCEPTS)

                # READS
                for v in getattr(fnlike, "state_variables_read", []) or []:
                    v_can = str(getattr(v, "canonical_name", "")) or str(
                        getattr(v, "name", "")
                    )
                    v_node = self._var_map.get(v_can)
                    if v_node:
                        g.add_edge(src_id, v_node, EdgeKind.READS)

                # WRITES
                for v in getattr(fnlike, "state_variables_written", []) or []:
                    v_can = str(getattr(v, "canonical_name", "")) or str(
                        getattr(v, "name", "")
                    )
                    v_node = self._var_map.get(v_can)
                    if v_node:
                        g.add_edge(src_id, v_node, EdgeKind.WRITES)

                # CALLS (internal)
                for ir in getattr(fnlike, "internal_calls", []) or []:
                    callee = getattr(ir, "function", None)
                    if callee is None:
                        continue
                    dst = self._get_unit_id(callee)
                    if dst:
                        g.add_edge(src_id, dst, EdgeKind.CALLS)

                # CALLS (high-level / external)
                for target_contract, call in (
                    getattr(fnlike, "high_level_calls", []) or []
                ):
                    fn_obj = getattr(call, "function", None)
                    dst = self._get_unit_id(fn_obj) if fn_obj else None
                    if dst:
                        g.add_edge(src_id, dst, EdgeKind.CALLS)
                    elif include_external:
                        fn_name = str(getattr(call, "function_name", "unknown"))
                        ext_id = f"external:call:{fn_name}"
                        if ext_id not in g._nodes:
                            g.add_node(
                                Node(id=ext_id, kind=NodeKind.EXTERNAL, name=fn_name)
                            )
                        g.add_edge(src_id, ext_id, EdgeKind.CALLS)

                # CALLS (library)
                for lib_call in getattr(fnlike, "library_calls", []) or []:
                    _, lib_fn = (
                        lib_call
                        if isinstance(lib_call, tuple) and len(lib_call) == 2
                        else (None, lib_call)
                    )
                    if lib_fn:
                        dst = self._get_unit_id(lib_fn)
                        if dst:
                            g.add_edge(src_id, dst, EdgeKind.CALLS)

                # EMITS
                emitted = self._get_emitted_events(fnlike)
                for evt_name in emitted:
                    for evt_can, evt_id in self._event_map.items():
                        if evt_can.endswith(f".{evt_name}") or evt_name == evt_can:
                            g.add_edge(src_id, evt_id, EdgeKind.EMITS)
                            break

                # USES_TYPE (from function signature)
                src_node = g._nodes.get(src_id)
                if src_node and src_node.meta.get("type_refs"):
                    for type_can in src_node.meta["type_refs"]:
                        type_id = self._type_map.get(type_can)
                        if type_id:
                            g.add_edge(src_id, type_id, EdgeKind.USES_TYPE)

    # --- Helpers ---

    def _get_unit_id(self, obj: Any) -> Optional[str]:
        """Get node ID for a function/modifier object."""
        oid = getattr(obj, "id", None)
        if oid is None:
            return None
        oid = int(oid)
        return self._func_map.get(oid) or self._mod_map.get(oid)

    def _ensure_ir(self, fnlike: Any) -> None:
        """Ensure IR is generated."""
        try:
            fnlike.generate_slithir_and_analyze()
        except Exception:
            pass

    def _get_emitted_events(self, fnlike: Any) -> Set[str]:
        """Extract emitted event names from function."""
        emitted: Set[str] = set()

        # IR-level
        for node in getattr(fnlike, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                if type(ir).__name__ == "EventCall":
                    evt_name = str(getattr(ir, "name", ""))
                    if evt_name:
                        emitted.add(evt_name)

        # Fallback
        if not emitted:
            for evt in getattr(fnlike, "events_emitted", []) or []:
                evt_name = str(getattr(evt, "name", ""))
                if evt_name:
                    emitted.add(evt_name)

        return emitted

    def _extract_type_refs(self, f: Any) -> List[str]:
        """Extract referenced type canonical names from function signature."""
        refs = []
        for param in list(getattr(f, "parameters", []) or []) + list(
            getattr(f, "returns", []) or []
        ):
            ptype = getattr(param, "type", None)
            if ptype and hasattr(ptype, "type"):
                # User-defined type
                inner = getattr(ptype, "type", None)
                if inner and hasattr(inner, "canonical_name"):
                    refs.append(str(inner.canonical_name))
        return refs

    def _parse_imports(self, code: str) -> List[str]:
        """Parse import statements from Solidity code."""
        out = []
        for m in _IMPORT_RE.finditer(code or ""):
            p = m.group("p1") or m.group("p2") or m.group("p3")
            if p:
                out.append(p.strip())
        return out

    def _resolve_import(
        self, imp: str, from_file: str, all_files: Set[str]
    ) -> Optional[str]:
        """Resolve import path to a file."""
        imp = imp.replace("\\", "/").strip()

        if imp.startswith((".", "..")):
            base = str(Path(from_file).parent)
            norm = str(Path(base, imp))
            if norm in all_files:
                return norm
            cands = [f for f in all_files if f.endswith(norm)]
            return cands[0] if len(cands) == 1 else None

        if imp in all_files:
            return imp
        cands = [f for f in all_files if f.endswith(imp)]
        if cands:
            cands.sort(key=len)
            return cands[0]
        return None
