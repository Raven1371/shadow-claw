"""Data-flow diagram generation.

Always writes ``.dot`` (Graphviz) and ``.mmd`` (Mermaid) sources.  If the
Graphviz ``dot`` binary is installed, SVG and PNG are rendered from the DOT
source using a list-argument subprocess call (no shell involved); otherwise a
helpful installation message is returned instead of crashing.
"""

from __future__ import annotations

import logging
import math
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import DISCLAIMER
from .config import AnalyzerConfig
from .models import EvidenceClass, Flow, Host, ScanMetadata, ip_sort_key
from .output_safety import atomic_replace_file, atomic_write_text, create_secure_temp_file
from .sanitization import escape_dot_label, escape_mermaid_label

LOG = logging.getLogger("nmap_flow_analyzer.diagrams")

#: evidence class -> (graphviz style, color, mermaid dash array)
EDGE_STYLES: Dict[str, Tuple[str, str, str]] = {
    EvidenceClass.OBSERVED.value: ("solid", "#24292f", ""),
    EvidenceClass.INFERRED.value: ("dashed", "#0969da", "6 4"),
    EvidenceClass.USER_DEFINED.value: ("dotted", "#1a7f37", "2 4"),
    EvidenceClass.UNKNOWN.value: ("dashed", "#9a6700", "10 4"),
    EvidenceClass.MANUAL_REVIEW.value: ("dashed", "#cf222e", "10 4"),
}

#: Zeek-mode edge kinds -> (graphviz style, color, mermaid dash array)
ZEEK_EDGE_STYLES: Dict[str, Tuple[str, str, str]] = {
    "nmap-scanner-reachability": ("solid", "#6e7781", "1 3"),
    "zeek-observed-traffic": ("solid", "#1a7f37", ""),
    "corroborated-nmap-and-zeek": ("bold", "#0a3069", ""),
    "declared-not-observed": ("dotted", "#8250df", "2 4"),
    "inferred": ("dashed", "#0969da", "6 4"),
    "attempted-or-failed": ("dashed", "#cf222e", "4 3"),
    "manual-review": ("dashed", "#bc4c00", "10 4"),
}


def edge_kind(flow: Flow) -> str:
    """Classify a flow into a Zeek-mode diagram edge kind.

    The arrow direction always represents the *initiator*; a response is
    never drawn as a second arrow.
    """
    if flow.correlation_status == "attempted-only":
        return "attempted-or-failed"
    if flow.evidence_class == EvidenceClass.MANUAL_REVIEW.value:
        return "manual-review"
    has_zeek = "zeek" in flow.evidence_sources
    if has_zeek and flow.zeek_observation.startswith("scanner-generated"):
        return "nmap-scanner-reachability"
    if flow.correlation_status in ("nmap-and-zeek", "user-defined-and-zeek") and has_zeek:
        return "corroborated-nmap-and-zeek"
    if has_zeek:
        return "zeek-observed-traffic"
    if flow.evidence_class == EvidenceClass.USER_DEFINED.value:
        return "declared-not-observed"
    if flow.evidence_class == EvidenceClass.INFERRED.value:
        return "inferred"
    return "nmap-scanner-reachability"


def _human_bytes(count: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024 or unit == "TB":
            return f"{count:.0f}{unit}" if unit == "B" else f"{count:.1f}{unit}"
        count /= 1024.0
    return "0B"


def bounded_penwidth(connection_count: int) -> float:
    """Bounded logarithmic edge thickness; huge counts stay readable."""
    if connection_count <= 0:
        return 1.0
    return round(min(4.0, 1.0 + math.log10(connection_count + 1)), 2)


MAX_EDGE_LABELS = 6

INSTALL_HINT = (
    "Graphviz 'dot' binary not found: SVG/PNG diagrams were skipped, but the "
    ".dot and .mmd sources were written. Install Graphviz to render images:\n"
    "  Debian/Ubuntu: sudo apt install graphviz\n"
    "  RHEL/Fedora:   sudo dnf install graphviz\n"
    "  macOS:         brew install graphviz\n"
    "  Windows:       winget install Graphviz.Graphviz (or choco install graphviz)\n"
    "Then re-run, or render manually: dot -Tsvg data_flow_diagram.dot -o data_flow_diagram.svg"
)


@dataclass
class DiagramEdge:
    src: str
    dst: str
    evidence_class: str
    labels: List[str] = field(default_factory=list)
    flow_count: int = 0
    kind: str = ""            # zeek-mode edge kind ('' in Nmap-only mode)
    connection_count: int = 0
    bytes_total: int = 0


@dataclass
class DiagramResult:
    """Exactly what THIS run produced (never inferred from old files)."""

    dot_path: Optional[Path] = None
    mermaid_path: Optional[Path] = None
    svg_path: Optional[Path] = None
    png_path: Optional[Path] = None
    svg_rendered: bool = False
    png_rendered: bool = False
    graphviz_available: bool = False
    render_error: Optional[str] = None
    generated_paths: List[Path] = field(default_factory=list)
    # Backward-compatible aliases (v1.1.0 API):
    written: List[Path] = field(default_factory=list)
    message: str = ""
    rendered: bool = False  # True when SVG/PNG rendering succeeded


def _node_id(value: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9]", "_", value)


def _escape(value: str) -> str:
    """Escape untrusted text for a quoted DOT label (see sanitization module)."""
    return escape_dot_label(value)


def group_edges(flows: List[Flow], detail: str = "summary",
                zeek_active: bool = False) -> List[DiagramEdge]:
    """De-duplicate flows into diagram edges.

    One edge per (source, destination, evidence class); labels are combined
    services (summary) or protocol/port pairs (full), sorted and de-duplicated
    so multiple findings for the same flow never draw duplicate arrows.
    """
    grouped: Dict[Tuple[str, str, str], DiagramEdge] = {}
    for flow in flows:
        if zeek_active:
            kind = edge_kind(flow)
            key = (flow.source, flow.destination, kind)
        else:
            kind = ""
            key = (flow.source, flow.destination, flow.evidence_class)
        edge = grouped.setdefault(
            key, DiagramEdge(src=flow.source, dst=flow.destination,
                             evidence_class=flow.evidence_class, kind=kind)
        )
        if zeek_active:
            base = (flow.normalized_service or "?").strip()
            label = f"{base} {flow.protocol}/{flow.destination_port}"
            if flow.connection_count:
                label += f" (x{flow.connection_count})"
            if detail == "full":
                extras = []
                if flow.first_seen:
                    extras.append(f"first {flow.first_seen[:16]}")
                if flow.last_seen:
                    extras.append(f"last {flow.last_seen[:16]}")
                if flow.connection_count:
                    extras.append(
                        f"ok {flow.successful_connections}"
                        f"/fail {flow.failed_connections}"
                    )
                total = flow.originator_bytes + flow.responder_bytes
                if total:
                    extras.append(_human_bytes(total))
                name = (flow.tls_server_names or flow.http_hosts or [""])[0]
                if name:
                    extras.append(name[:40])
                if extras:
                    label += " | " + ", ".join(extras)
            label = label[:120]
        elif detail == "full":
            label = f"{flow.protocol}/{flow.destination_port} {flow.normalized_service}"
        else:
            label = flow.normalized_service or f"{flow.protocol}/{flow.destination_port}"
        if label not in edge.labels:
            edge.labels.append(label)
        edge.flow_count += 1
        edge.connection_count = max(edge.connection_count, flow.connection_count)
        edge.bytes_total += flow.originator_bytes + flow.responder_bytes
    edges = list(grouped.values())
    for edge in edges:
        edge.labels.sort()
    edges.sort(key=lambda e: (e.src, e.dst, e.kind, e.evidence_class))
    return edges


def _endpoints(
    flows: List[Flow], hosts: List[Host], config: AnalyzerConfig
) -> Dict[str, Tuple[str, str]]:
    """Map endpoint value -> (multi-line label, zone) for every diagram node."""
    by_ip = {h.primary_ip: h for h in hosts}
    endpoints: Dict[str, Tuple[str, str]] = {}
    for flow in flows:
        for value, name, zone in (
            (flow.source, flow.source_name, flow.source_zone),
            (flow.destination, flow.destination_name, flow.destination_zone),
        ):
            if value in endpoints:
                continue
            host = by_ip.get(value)
            if host is not None:
                lines = [host.display_name, host.primary_ip]
                if host.best_os:
                    lines.append(host.best_os[:32])
                role = host.role
                if role != "Unknown":
                    lines.append(f"{role} ({host.role_confidence}%)")
                endpoints[value] = ("\\n".join(_escape(l) for l in lines), host.zone)
            else:
                label = name if name and name != value else value
                if label != value:
                    label = f"{label}\\n{value}"
                endpoints[value] = (_escape(label), zone or "Unknown")
    return endpoints


def build_dot(
    hosts: List[Host],
    flows: List[Flow],
    metadata: ScanMetadata,
    config: AnalyzerConfig,
    detail: str = "summary",
    zeek_active: bool = False,
) -> str:
    """Build the Graphviz DOT source."""
    endpoints = _endpoints(flows, hosts, config)
    edges = group_edges(flows, detail, zeek_active=zeek_active)

    zones: Dict[str, List[str]] = {}
    for value, (_, zone) in endpoints.items():
        zones.setdefault(zone or "Unknown", []).append(value)

    origin = config.scanner_ip or "not configured"
    diagram_title = ("Network Data-Flow Diagram (Nmap + Zeek)" if zeek_active
                     else "Network Data-Flow Diagram (Nmap-derived)")
    title_lines = [
        diagram_title,
        f"Scan origin: {origin}    Scan started: {metadata.start_time or 'unknown'}",
        DISCLAIMER,
    ]
    out: List[str] = [
        "digraph nmap_flows {",
        '  rankdir=LR;',
        '  fontname="Helvetica"; fontsize=11;',
        '  node [shape=box, style="rounded,filled", fillcolor="#f6f8fa", '
        'fontname="Helvetica", fontsize=10];',
        '  edge [fontname="Helvetica", fontsize=9];',
        f'  label="{_escape(chr(10).join(title_lines))}"; labelloc="b";',  # newlines escaped
    ]

    external_zone = config.zeek.external_zone_name if zeek_active else None
    for index, zone in enumerate(sorted(zones)):
        is_external = external_zone is not None and zone == external_zone
        color = "#cf222e" if is_external else "#8c959f"
        out.append(f'  subgraph cluster_zone_{index} {{')
        out.append(f'    label="Zone: {_escape(zone)}'
                   f'{" (external)" if is_external else ""}"; '
                   f'color="{color}"; style="rounded{",dashed" if is_external else ""}";')
        for value in sorted(zones[zone], key=lambda v: ip_sort_key(v.split("/")[0])):
            label, _ = endpoints[value]
            fill = ' fillcolor="#ffebe9"' if is_external else ""
            out.append(f'    {_node_id(value)} [label="{label}"{fill}];')
        out.append("  }")

    for edge in edges:
        if zeek_active:
            style, color, _ = ZEEK_EDGE_STYLES.get(
                edge.kind, ZEEK_EDGE_STYLES["manual-review"]
            )
        else:
            style, color, _ = EDGE_STYLES.get(
                edge.evidence_class, EDGE_STYLES[EvidenceClass.UNKNOWN.value]
            )
        labels = edge.labels[:MAX_EDGE_LABELS]
        if len(edge.labels) > MAX_EDGE_LABELS:
            labels.append(f"+{len(edge.labels) - MAX_EDGE_LABELS} more")
        label = _escape("\n".join(labels)).replace("\n", "\\n")
        if zeek_active:
            extra = f' penwidth={bounded_penwidth(edge.connection_count)}'
        else:
            extra = (' penwidth=1.6'
                     if edge.evidence_class == EvidenceClass.MANUAL_REVIEW.value
                     else "")
        out.append(
            f'  {_node_id(edge.src)} -> {_node_id(edge.dst)} '
            f'[label="{label}", style={style}, color="{color}", '
            f'fontcolor="{color}"{extra}];'
        )

    # Legend
    out.append('  subgraph cluster_legend {')
    out.append('    label="Legend"; color="#8c959f"; fontsize=10;')
    out.append('    node [shape=plaintext, fillcolor=white, style=""];')
    legend_styles = ZEEK_EDGE_STYLES if zeek_active else EDGE_STYLES
    for index, (klass, (style, color, _)) in enumerate(sorted(legend_styles.items())):
        a, b = f"leg_a_{index}", f"leg_b_{index}"
        out.append(f'    {a} [label=""]; {b} [label="{_escape(klass)}"];')
        out.append(f'    {a} -> {b} [style={style}, color="{color}"];')
    out.append("  }")
    out.append("}")
    return "\n".join(out) + "\n"


def build_mermaid(
    hosts: List[Host],
    flows: List[Flow],
    metadata: ScanMetadata,
    config: AnalyzerConfig,
    detail: str = "summary",
    zeek_active: bool = False,
) -> str:
    """Build Mermaid flowchart source as a portable secondary format."""
    endpoints = _endpoints(flows, hosts, config)
    edges = group_edges(flows, detail, zeek_active=zeek_active)
    zones: Dict[str, List[str]] = {}
    for value, (_, zone) in endpoints.items():
        zones.setdefault(zone or "Unknown", []).append(value)

    out: List[str] = [
        ("%% Network Data-Flow Diagram (Nmap + Zeek)" if zeek_active
         else "%% Network data-flow diagram (Nmap-derived)"),
        f"%% Scan origin: {config.scanner_ip or 'not configured'}; "
        f"started: {metadata.start_time or 'unknown'}",
        f"%% {DISCLAIMER}",
        *(
            [
                "%% green solid = Zeek-observed traffic, "
                "blue bold = corroborated Nmap+Zeek,",
                "%% grey dash 1-3 = Nmap scanner reachability, "
                "purple dash 2-4 = declared not observed,",
                "%% blue dash 6-4 = inferred, red dash 4-3 = attempted/failed, "
                "orange dash 10-4 = manual review",
            ]
            if zeek_active else [
                "%% Solid = Observed, dash 6-4 = Inferred, dash 2-4 = User-Defined,",
                "%% dash 10-4 = Unknown / Manual Review Required",
            ]
        ),
        "flowchart LR",
    ]
    for index, zone in enumerate(sorted(zones)):
        out.append(f'  subgraph zone{index}["Zone: {zone}"]')
        for value in sorted(zones[zone], key=lambda v: ip_sort_key(v.split("/")[0])):
            label = escape_mermaid_label(endpoints[value][0].replace("\\n", "\n"))
            out.append(f'    {_node_id(value)}["{label}"]')
        out.append("  end")

    link_styles: List[str] = []
    for index, edge in enumerate(edges):
        labels = edge.labels[:MAX_EDGE_LABELS]
        if len(edge.labels) > MAX_EDGE_LABELS:
            labels.append(f"+{len(edge.labels) - MAX_EDGE_LABELS} more")
        label = "<br/>".join(escape_mermaid_label(l) for l in labels)
        out.append(f'  {_node_id(edge.src)} -->|"{label}"| {_node_id(edge.dst)}')
        if zeek_active:
            style, color, dash = ZEEK_EDGE_STYLES.get(
                edge.kind, ZEEK_EDGE_STYLES["manual-review"]
            )
        else:
            style, color, dash = EDGE_STYLES.get(
                edge.evidence_class, EDGE_STYLES[EvidenceClass.UNKNOWN.value]
            )
        rule = f"stroke:{color}"
        if zeek_active:
            rule += f",stroke-width:{bounded_penwidth(edge.connection_count)}px"
        if dash:
            rule += f",stroke-dasharray:{dash}"
        link_styles.append(f"  linkStyle {index} {rule}")
    out.extend(link_styles)
    return "\n".join(out) + "\n"


def _render(
    dot_path: Path, out_path: Path, fmt: str, timeout: int = 60
) -> Optional[str]:
    """Render with the Graphviz binary; returns an error message or None.

    Never hangs the run: rendering is bounded by ``timeout`` seconds
    (``--graphviz-timeout``).  Any failure leaves the .dot/.mmd sources in
    place so the diagram can still be rendered elsewhere.
    """
    dot_bin = shutil.which("dot")
    if not dot_bin:
        return INSTALL_HINT
    # Render to a temp name inside the same directory; publish atomically
    # only on success so a timeout or crash never leaves partial output and
    # never disturbs an existing file until the new one is complete.
    tmp = create_secure_temp_file(out_path.parent, suffix=f".{fmt}")
    try:
        result = subprocess.run(
            [dot_bin, f"-T{fmt}", str(dot_path), "-o", str(tmp)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        tmp.unlink(missing_ok=True)
        return (
            f"Graphviz rendering timed out after {timeout}s "
            "(increase with --graphviz-timeout); .dot/.mmd sources were kept"
        )
    except (OSError, subprocess.SubprocessError) as exc:
        tmp.unlink(missing_ok=True)
        return f"Graphviz rendering failed: {exc}; .dot/.mmd sources were kept"
    if result.returncode != 0:
        tmp.unlink(missing_ok=True)
        return (
            f"Graphviz exited with status {result.returncode}: "
            f"{result.stderr.strip()[:400]}; .dot/.mmd sources were kept"
        )
    if not (tmp.exists() and tmp.is_file() and not tmp.is_symlink()):
        tmp.unlink(missing_ok=True)
        return "Graphviz reported success but produced no regular output file"
    try:
        atomic_replace_file(tmp, out_path)
    except Exception as exc:  # OutputSafetyError or OSError
        tmp.unlink(missing_ok=True)
        return f"Could not publish rendered {fmt}: {exc}"
    return None


def write_diagrams(
    hosts: List[Host],
    flows: List[Flow],
    metadata: ScanMetadata,
    config: AnalyzerConfig,
    output_dir: Path,
    detail: str = "summary",
    graphviz_timeout: int = 60,
    zeek_active: bool = False,
) -> DiagramResult:
    """Write .dot/.mmd sources and render .svg/.png when Graphviz is present."""
    result = DiagramResult()
    dot_path = output_dir / "data_flow_diagram.dot"
    mmd_path = output_dir / "data_flow_diagram.mmd"
    atomic_write_text(dot_path, build_dot(hosts, flows, metadata, config, detail,
                                          zeek_active=zeek_active))
    atomic_write_text(mmd_path, build_mermaid(hosts, flows, metadata, config,
                                              detail, zeek_active=zeek_active))
    result.dot_path, result.mermaid_path = dot_path, mmd_path
    result.written.extend([dot_path, mmd_path])
    result.graphviz_available = shutil.which("dot") is not None

    messages: List[str] = []
    for fmt in ("svg", "png"):
        target = output_dir / f"data_flow_diagram.{fmt}"
        error = _render(dot_path, target, fmt, timeout=graphviz_timeout)
        if error is None:
            result.written.append(target)
            if fmt == "svg":
                result.svg_path, result.svg_rendered = target, True
            else:
                result.png_path, result.png_rendered = target, True
        else:
            messages.append(error)
            LOG.warning("%s", error)
            break  # same cause for both formats; report once
    result.message = messages[0] if messages else ""
    result.render_error = messages[0] if messages else None
    result.rendered = not messages
    result.generated_paths = list(result.written)
    LOG.info("Diagram files written: %s", ", ".join(p.name for p in result.written))
    return result
