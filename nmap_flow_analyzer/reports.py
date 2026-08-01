"""Report writers: CSV, JSON, Markdown summary, normalized data, and a
self-contained HTML report (no external CDN, searchable/sortable tables,
print-friendly styling)."""

from __future__ import annotations

import csv
import dataclasses
import datetime
import html
import os
import tempfile
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import COMBINED_DISCLAIMER, DISCLAIMER, TOOL_NAME, __version__
from .pluralize import count_noun, has, plural, verb, were
from .config import AnalyzerConfig
from .flow_analysis import AnalysisOptions
PERSPECTIVE_NOTE = (
    "A user-defined or inferred dependency may require both a source-side "
    "outbound rule and a destination-side inbound rule, depending on the "
    "enforcement architecture."
)

from .output_safety import atomic_write_text as _atomic_write_text
from .sanitization import (
    escape_markdown_inline,
    sanitize_row,
)
from .models import (
    EvidenceClass,
    FirewallRule,
    Flow,
    Host,
    ManualReviewItem,
    RISK_ORDER,
    ScanMetadata,
    ServiceRecord,
    VulnFinding,
    as_flat_dict,
    field_names,
)

LOG = logging.getLogger("nmap_flow_analyzer.reports")


# ---------------------------------------------------------------------------
# Generic writers
# ---------------------------------------------------------------------------

def atomic_write_text(path: Path, text: str) -> None:
    """Validated, fsynced, atomic text write (see output_safety module).

    A failure mid-write never leaves a truncated report behind, the
    temporary file is removed on error, and symlink destinations are
    rejected before replacement.
    """
    _atomic_write_text(path, text)


def write_csv(
    path: Path, rows: Sequence[Any], cls: type, sanitize: bool = True
) -> None:
    """Write a CSV atomically, spreadsheet-safe by default.

    String cells that could be interpreted as formulas by spreadsheet
    software are prefixed (see sanitization module); numeric values,
    IPs/CIDRs, and timestamps are untouched.
    """
    import io

    columns = field_names(cls)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns)
    writer.writeheader()
    for row in rows:
        writer.writerow(sanitize_row(as_flat_dict(row), enabled=sanitize))
    atomic_write_text(path, buffer.getvalue())
    LOG.debug("Wrote %s (%s)", path.name, count_noun(len(rows), "row"))


def write_json_object(path: Path, payload: Dict[str, Any]) -> None:
    """Atomically write an arbitrary JSON-serializable mapping."""
    atomic_write_text(
        path, json.dumps(payload, indent=2, sort_keys=False) + "\n"
    )


def write_json(path: Path, rows: Sequence[Any]) -> None:
    data = [dataclasses.asdict(row) for row in rows]
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    LOG.debug("Wrote %s (%s)", path.name, count_noun(len(rows), "record"))


# ---------------------------------------------------------------------------
# Assumptions
# ---------------------------------------------------------------------------

def build_assumptions(config: AnalyzerConfig, options: AnalysisOptions) -> List[str]:
    assumptions = [
        "Nmap results record reachability from the scanner's location at scan "
        "time; they are not a passive record of production traffic.",
        "Only ports reported 'open' are treated as confirmed reachable; "
        "'open|filtered' ports are uncertain and always require manual review; "
        "'filtered' and 'closed' ports never generate allow rules.",
    ]
    if config.scanner_ip:
        assumptions.append(
            f"The scan originated from {config.scanner_ip}"
            + (f" ({config.scanner_hostname})" if config.scanner_hostname else "")
            + (f" in zone '{config.scanner_zone}'" if config.scanner_zone else "")
            + ", as declared by the operator (not derivable from the XML)."
        )
    else:
        assumptions.append(
            "The scanner's own IP address was not provided; observed flows use an "
            "unverified scanner placeholder and their rules require manual review."
        )
    assumptions.append(
        f"Firewall mode is '{options.firewall_mode}': "
        + (
            "no separate rules are generated for normal response traffic."
            if options.firewall_mode == "stateful"
            else "explicit return-path rules are generated and labeled as such."
        )
    )
    if options.include_inferred_outbound:
        assumptions.append(
            "Inferred outbound dependencies are enabled: flows to configured "
            "infrastructure servers (DNS, NTP, domain controllers, logging, "
            "patching, backup, mail relay, proxy, authentication) are generated "
            "as 'Inferred' and must be validated before implementation."
        )
    else:
        assumptions.append(
            "Inferred outbound dependencies are disabled; outbound rules come "
            "only from the configuration (or stateless return paths)."
        )
    if options.include_open_filtered:
        assumptions.append(
            "open|filtered ports are included as 'Manual Review Required' flows "
            "at the operator's request; none produce candidate rules."
        )
    if options.strict:
        assumptions.append(
            "Strict mode is on: overly broad or ambiguous rules were moved to "
            "manual review instead of the proposed exception lists."
        )
    if config.zones:
        assumptions.append(
            "Security zones were mapped from the configuration file "
            f"({', '.join(sorted(config.zones))}); hosts outside declared ranges "
            "are 'Internal' (local ranges) or 'Unknown'."
        )
    else:
        assumptions.append("No security zones were configured; all zones are 'Unknown'.")
    return assumptions


# ---------------------------------------------------------------------------
# Markdown summary
# ---------------------------------------------------------------------------

def write_findings_summary(
    path: Path,
    metadata: ScanMetadata,
    hosts: List[Host],
    services: List[ServiceRecord],
    flows: List[Flow],
    inbound: List[FirewallRule],
    outbound: List[FirewallRule],
    reviews: List[ManualReviewItem],
    vulns: List[VulnFinding],
    assumptions: List[str],
    run_status: Optional[Dict[str, str]] = None,
    zeek: Optional[Any] = None,
) -> None:
    open_services = [s for s in services if s.state == "open"]
    high = [
        s for s in open_services if RISK_ORDER[s.risk_level] >= RISK_ORDER["High"]
    ]
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    active_disclaimer = COMBINED_DISCLAIMER if zeek is not None else DISCLAIMER
    lines = [
        "# Nmap Flow Analysis - Findings Summary",
        "",
        f"Generated {generated} by {TOOL_NAME} {__version__}.",
        "",
        f"> {active_disclaimer}",
        "",
        "## Scan metadata",
        "",
        f"- Command line: `{escape_markdown_inline(metadata.command_line or 'unknown')}`",
        f"- Nmap version: {escape_markdown_inline(metadata.nmap_version or 'unknown')}",
        f"- Started: {escape_markdown_inline(metadata.start_time or 'unknown')}; finished: "
        f"{escape_markdown_inline(metadata.end_time or 'unknown')} "
        f"({escape_markdown_inline(metadata.summary or 'no summary')})",
        f"- Scan types: {', '.join(metadata.scan_types) or 'unknown'}",
        "",
        "## Counts",
        "",
        f"- Hosts parsed: {len(hosts)}",
        f"- Open services: {len(open_services)}",
        f"- Flows modeled: {len(flows)} "
        f"(Observed {sum(1 for f in flows if f.evidence_class == EvidenceClass.OBSERVED.value)}, "
        f"Inferred {sum(1 for f in flows if f.evidence_class == EvidenceClass.INFERRED.value)}, "
        f"User-Defined {sum(1 for f in flows if f.evidence_class == EvidenceClass.USER_DEFINED.value)})",
        f"- Candidate inbound rules: {len(inbound)}",
        f"- Candidate outbound rules: {len(outbound)}",
        f"- Manual-review items: {len(reviews)}",
        f"- NSE security-relevant findings: {len(vulns)}",
        "",
    ]
    if zeek is not None:
        successful_aggs = sum(1 for a in zeek.aggregates if a.successful_count)
        failed_only = sum(
            1 for a in zeek.aggregates
            if (a.failed_count + a.rejected_count) and not a.successful_count
        )
        from .zeek_correlation import (
            count_communications, evidence_overlap_breakdown,
            supported_by_nmap_and_zeek,
        )

        corroborated_flows = [
            f for f in flows if supported_by_nmap_and_zeek(f)
        ]
        zeek_only_flows = [
            f for f in flows if f.correlation_status == "zeek-traffic-only"
        ]
        conflicting_flows = [
            f for f in flows if f.correlation_status == "conflicting-evidence"
        ]
        md_overlap = evidence_overlap_breakdown(flows)
        corroborated = md_overlap["supported_by_nmap_and_zeek"]
        zeek_only = count_communications(zeek_only_flows)
        unobserved = sum(
            1 for s in services
            if s.state == "open" and s.zeek_observation.startswith("Not observed")
        )
        scanner_only = sum(
            1 for s in services
            if s.state == "open" and s.scanner_only_zeek_traffic_observed
        )
        production_observed = sum(
            1 for s in services
            if s.state == "open" and s.non_scanner_zeek_traffic_observed
        )
        lines += [
            "## Zeek correlation summary",
            "",
            f"- Zeek observation window (UTC): "
            f"{escape_markdown_inline(zeek.metadata.earliest_timestamp or 'unknown')} to "
            f"{escape_markdown_inline(zeek.metadata.latest_timestamp or 'unknown')}",
            f"- Zeek endpoints observed: {len(zeek.endpoints)}",
            f"- Zeek aggregated flows: {len(zeek.aggregates)} "
            f"({successful_aggs} with successful connections, "
            f"{failed_only} failed/rejected only)",
            f"- Communications supported by both Nmap and Zeek "
            f"(evidence-source overlap, any primary status): {corroborated} "
            f"unique ({len(corroborated_flows)} firewall perspectives)",
            f"  - Nmap-and-Zeek only: "
            f"{md_overlap['nmap_and_zeek_only']}",
            f"  - Declared and observed with Nmap corroboration: "
            f"{md_overlap['declared_with_nmap_corroboration']}",
            f"  - Inferred and observed with Nmap corroboration: "
            f"{md_overlap['inferred_with_nmap_corroboration']}",
            f"- Zeek-only communications: {zeek_only} unique "
            f"({len(zeek_only_flows)} firewall perspectives)",
            f"- Conflicting-evidence communications (rules withheld): "
            f"{count_communications(conflicting_flows)} unique "
            f"({len(conflicting_flows)} perspectives)",
            f"- Nmap-exposed services with non-scanner production traffic: "
            f"{production_observed}",
            f"- Nmap-exposed services seen only in scanner-generated traffic: "
            f"{scanner_only} (not production usage, and not evidence of "
            f"disuse)",
            f"- Nmap-exposed services with no Zeek traffic at all: "
            f"{unobserved} (not evidence they are unused)",
            f"- External dependencies: {len(zeek.external_dependencies)}",
            f"- Correlation findings: {len(zeek.findings)}",
            f"- Zeek sensor health: "
            f"{escape_markdown_inline(zeek.health.status)}"
            + (f" ({escape_markdown_inline('; '.join(zeek.health.notes[:1]))})"
               if zeek.health.notes else ""),
            "",
        ]
    lines += [
        "## High- and critical-risk exposed services",
        "",
    ]
    if high:
        for s in sorted(high, key=lambda s: (-RISK_ORDER[s.risk_level], s.ip, s.port)):
            lines.append(
                f"- **{s.risk_level}** - {escape_markdown_inline(s.hostname)} ({s.ip}) "
                f"{s.protocol}/{s.port} {escape_markdown_inline(s.normalized_service)}: "
                f"{escape_markdown_inline('; '.join(s.risk_reasons))}"
            )
    else:
        lines.append("- None identified by the configured risk rules.")
    lines += ["", "## Manual review required", ""]
    if reviews:
        for item in reviews:
            location = f" ({item.ip} {item.protocol}/{item.port})" if item.ip else ""
            lines.append(f"- **{item.item_id}** [{escape_markdown_inline(item.category)}]{location}: "
                         f"{escape_markdown_inline(item.finding)} - {escape_markdown_inline(item.reason)}")
    else:
        lines.append("- No manual-review items.")
    if run_status:
        lines += ["", "## Run status", ""]
        lines.extend(
            f"- {escape_markdown_inline(k)}: {escape_markdown_inline(v)}"
            for k, v in run_status.items()
        )
    lines += ["", "## Assumptions", ""]
    lines.extend(f"- {escape_markdown_inline(a)}" for a in assumptions)
    lines.append("")
    atomic_write_text(path, "\n".join(lines))
    LOG.debug("Wrote %s", path.name)


# ---------------------------------------------------------------------------
# Normalized data
# ---------------------------------------------------------------------------

def write_normalized_data(
    path: Path,
    metadata: ScanMetadata,
    hosts: List[Host],
    services: List[ServiceRecord],
    flows: List[Flow],
    inbound: List[FirewallRule],
    outbound: List[FirewallRule],
    reviews: List[ManualReviewItem],
    vulns: List[VulnFinding],
    assumptions: List[str],
    run_status: Optional[Dict[str, str]] = None,
    extra_sections: Optional[Dict[str, Any]] = None,
    zeek: Optional[Any] = None,
) -> None:
    active_disclaimer = COMBINED_DISCLAIMER if zeek is not None else DISCLAIMER
    payload = {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "disclaimer": active_disclaimer,
        "scan_metadata": dataclasses.asdict(metadata),
        "hosts": [dataclasses.asdict(h) for h in hosts],
        "service_inventory": [dataclasses.asdict(s) for s in services],
        "flows": [dataclasses.asdict(f) for f in flows],
        "inbound_rules": [dataclasses.asdict(r) for r in inbound],
        "outbound_rules": [dataclasses.asdict(r) for r in outbound],
        "manual_review": [dataclasses.asdict(m) for m in reviews],
        "vulnerability_findings": [dataclasses.asdict(v) for v in vulns],
        "assumptions": assumptions,
        "run_status": run_status or {},
    }
    # v1.2.0: append-only Zeek sections (bounded aggregates and samples,
    # never raw log records).
    for key, value in (extra_sections or {}).items():
        payload[key] = value
    atomic_write_text(
        path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    )
    LOG.debug("Wrote %s", path.name)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_CSS = """
:root { --ink:#1f2933; --line:#d5dbe1; --accent:#0b4f6c; --soft:#eef2f5; }
* { box-sizing:border-box; }
body { font-family:Georgia,'Times New Roman',serif; color:var(--ink);
       margin:0; background:#fbfcfd; line-height:1.5; }
header { background:var(--accent); color:#fff; padding:28px 36px; }
header h1 { margin:0 0 6px; font-size:26px; font-weight:normal;
            letter-spacing:.3px; }
header .meta { font-family:Verdana,Arial,sans-serif; font-size:12px;
               opacity:.92; }
main { max-width:1180px; margin:0 auto; padding:24px 36px 64px; }
.disclaimer { border-left:4px solid var(--accent); background:var(--soft);
              padding:12px 16px; font-style:italic; margin:18px 0 28px; }
h2 { font-size:20px; border-bottom:2px solid var(--line); padding-bottom:6px;
     margin-top:40px; font-weight:normal; }
h2 .count { font-family:Verdana,Arial,sans-serif; font-size:12px;
            color:#5f6b76; }
p, li { max-width:76ch; }
input.tbl-filter { font-family:Verdana,Arial,sans-serif; font-size:12px;
  padding:6px 10px; margin:10px 0 6px; width:320px; max-width:100%;
  border:1px solid var(--line); border-radius:3px; }
.tbl-wrap { overflow-x:auto; border:1px solid var(--line); border-radius:3px;
            background:#fff; }
table { border-collapse:collapse; width:100%;
        font-family:Verdana,Arial,sans-serif; font-size:11.5px; }
th { background:var(--soft); text-align:left; padding:7px 9px; cursor:pointer;
     border-bottom:2px solid var(--line); white-space:nowrap;
     position:sticky; top:0; }
th:hover { background:#e2e8ee; }
td { padding:6px 9px; border-bottom:1px solid #eceff2; vertical-align:top; }
tr:nth-child(even) td { background:#fafbfc; }
.badge { display:inline-block; padding:1px 7px; border-radius:9px;
         font-size:10.5px; white-space:nowrap; border:1px solid transparent; }
.b-Observed { background:#e7f0e9; color:#1a5632; border-color:#bcd9c5; }
.b-Inferred { background:#e4eefb; color:#0b4f8a; border-color:#bcd4ef; }
.b-UserDefined { background:#efe9f7; color:#4a2d7a; border-color:#d7c9ec; }
.b-Unknown { background:#f3f0e4; color:#6b5a13; border-color:#e0d8b8; }
.b-ManualReview { background:#fbe9e7; color:#8a1f11; border-color:#efc4bd; }
.r-Critical { color:#8a1f11; font-weight:bold; }
.r-High { color:#b23c17; font-weight:bold; }
.r-Medium { color:#8a6d00; }
.r-Low { color:#1a5632; }
.r-Informational { color:#5f6b76; }
figure.diagram { margin:16px 0; border:1px solid var(--line); background:#fff;
                 padding:12px; overflow-x:auto; }
figure.diagram svg { max-width:100%; height:auto; }
footer { text-align:center; font-family:Verdana,Arial,sans-serif;
         font-size:11px; color:#5f6b76; padding:20px; }
@media print {
  header { background:#fff; color:var(--ink);
           border-bottom:3px double var(--ink); }
  input.tbl-filter { display:none; }
  th { position:static; }
  .tbl-wrap { border:none; overflow:visible; }
  body { background:#fff; }
  h2 { page-break-after:avoid; }
  tr { page-break-inside:avoid; }
}
"""

_JS = """
document.querySelectorAll('input.tbl-filter').forEach(function (inp) {
  inp.addEventListener('input', function () {
    var table = document.getElementById(inp.dataset.table);
    if (!table) { return; }
    var query = inp.value.toLowerCase();
    table.querySelectorAll('tbody tr').forEach(function (row) {
      row.style.display =
        row.textContent.toLowerCase().indexOf(query) !== -1 ? '' : 'none';
    });
  });
});
document.querySelectorAll('table.sortable th').forEach(function (th) {
  th.title = 'Click to sort';
  th.addEventListener('click', function () {
    var table = th.closest('table');
    var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
    var asc = th.dataset.asc !== '1';
    table.querySelectorAll('th').forEach(function (h) { h.dataset.asc = ''; });
    th.dataset.asc = asc ? '1' : '0';
    var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));
    rows.sort(function (a, b) {
      var x = a.children[idx].textContent.trim();
      var y = b.children[idx].textContent.trim();
      var nx = parseFloat(x), ny = parseFloat(y);
      var cmp = (!isNaN(nx) && !isNaN(ny) && x !== '' && y !== '')
        ? nx - ny : x.localeCompare(y);
      return asc ? cmp : -cmp;
    });
    var body = table.querySelector('tbody');
    rows.forEach(function (row) { body.appendChild(row); });
  });
});
"""


def _cell(value: Any, column: str) -> str:
    text = html.escape(str(value))
    if column == "evidence_class":
        css = "b-" + str(value).replace(" ", "").replace("-", "")
        return f'<span class="badge {css}">{text}</span>'
    if column == "risk_level":
        return f'<span class="r-{html.escape(str(value))}">{text}</span>'
    return text


def _table(rows: Sequence[Dict[str, Any]], columns: Sequence[Tuple[str, str]], table_id: str) -> str:
    if not rows:
        return "<p><em>None.</em></p>"
    head = "".join(f"<th>{html.escape(label)}</th>" for _, label in columns)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{_cell(row.get(key, ''), key)}</td>" for key, _ in columns)
        body_rows.append(f"<tr>{cells}</tr>")
    return (
        f'<input class="tbl-filter" data-table="{table_id}" type="search" '
        f'placeholder="Filter {count_noun(len(rows), "row")}..." '
        'aria-label="Filter table">'
        f'<div class="tbl-wrap"><table id="{table_id}" class="sortable">'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody>"
        "</table></div>"
    )


def _section(title: str, count: Optional[int], body: str, note: str = "") -> str:
    count_html = f' <span class="count">({count})</span>' if count is not None else ""
    note_html = f"<p>{html.escape(note)}</p>" if note else ""
    return f"<h2>{html.escape(title)}{count_html}</h2>{note_html}{body}"


def write_html_report(
    path: Path,
    metadata: ScanMetadata,
    hosts: List[Host],
    services: List[ServiceRecord],
    flows: List[Flow],
    inbound: List[FirewallRule],
    outbound: List[FirewallRule],
    reviews: List[ManualReviewItem],
    vulns: List[VulnFinding],
    assumptions: List[str],
    svg_path: Optional[Path] = None,  # retained for API compatibility; unused
    run_status: Optional[Dict[str, str]] = None,
    diagram: Optional[Any] = None,  # DiagramResult from THIS run
    zeek: Optional[Any] = None,  # ZeekReportData for combined runs
) -> None:
    """Write the HTML report.

    The diagram image is included only when ``diagram`` (the current run's
    DiagramResult) says the SVG was rendered by this execution and the file
    passes safety checks.  A preexisting SVG on disk is never embedded or
    referenced — see CHANGELOG v1.1.1.  The image is referenced with
    ``<img src>`` rather than inlined, so even a hostile SVG cannot execute
    script in the report document context.
    """
    open_services = [s for s in services if s.state == "open"]
    observed = [f for f in flows if f.evidence_class == EvidenceClass.OBSERVED.value]
    inferred = [f for f in flows if f.evidence_class == EvidenceClass.INFERRED.value]
    other_flows = [
        f
        for f in flows
        if f.evidence_class
        not in {EvidenceClass.OBSERVED.value, EvidenceClass.INFERRED.value}
    ]
    high = sorted(
        (s for s in open_services if RISK_ORDER[s.risk_level] >= RISK_ORDER["High"]),
        key=lambda s: (-RISK_ORDER[s.risk_level], s.ip, s.port),
    )

    host_rows = [
        {
            "hostname": h.display_name,
            "ip": h.primary_ip,
            "zone": h.zone,
            "role": f"{h.role} ({h.role_confidence}%)" if h.role != "Unknown" else "Unknown",
            "role_source": h.role_source,
            "os": h.best_os,
            "mac_vendor": h.mac_vendor,
            "state": h.state,
            "open_ports": len(h.open_ports()),
            "owner": h.owner,
            "purpose": h.purpose,
        }
        for h in hosts
    ]
    service_cols = [
        ("hostname", "Host"), ("ip", "IP"), ("protocol", "Proto"), ("port", "Port"),
        ("state", "State"), ("normalized_service", "Service"),
        ("detected_service", "Detected"), ("product", "Product"),
        ("version", "Version"), ("risk_level", "Risk"),
        ("encryption", "Encryption"), ("evidence_class", "Evidence"),
    ]
    flow_cols = [
        ("flow_id", "ID"), ("source_name", "Source"), ("source", "Src IP/CIDR"),
        ("source_zone", "Src zone"), ("destination_name", "Destination"),
        ("destination", "Dst IP"), ("protocol", "Proto"),
        ("destination_port", "Port"), ("normalized_service", "Service"),
        ("evidence_class", "Evidence"), ("flow_evidence", "Combined evidence"),
        ("perspective", "Perspective"), ("confidence", "Conf."),
        ("risk_level", "Risk"), ("evidence", "Evidence detail"),
    ]
    rule_cols = [
        ("rule_id", "ID"), ("target_hostname", "Target"), ("target_ip", "Target IP"),
        ("source", "Source"), ("destination", "Destination"), ("protocol", "Proto"),
        ("port", "Port"), ("service", "Service"), ("purpose", "Purpose"),
        ("evidence_class", "Evidence"), ("flow_evidence", "Combined evidence"),
        ("service_evidence", "Service ev."), ("source_scope_evidence", "Src-scope ev."),
        ("destination_scope_evidence", "Dst-scope ev."),
        ("perspective", "Perspective"), ("confidence", "Conf."),
        ("risk_level", "Risk"),
        ("source_scope_status", "Src policy"), ("destination_scope_status", "Dst policy"),
        ("matched_source_policy", "Matched src policy"),
        ("matched_destination_policy", "Matched dst policy"),
        ("policy_violation", "Policy violation"),
        ("recommended_action", "Recommended action"),
        ("scope_warning", "Scope warning"), ("policy_notes", "Policy notes"),
    ]
    review_cols = [
        ("item_id", "ID"), ("category", "Category"), ("host", "Host"), ("ip", "IP"),
        ("protocol", "Proto"), ("port", "Port"), ("finding", "Finding"),
        ("reason", "Reason"), ("recommendation", "Recommendation"),
    ]
    vuln_cols = [
        ("host", "Host"), ("ip", "IP"), ("protocol", "Proto"), ("port", "Port"),
        ("script_id", "NSE script"), ("category", "Category"), ("excerpt", "Output (as reported)"),
    ]

    svg_html = (
        "<p><em>Diagram image rendering was unavailable for this run. "
        "DOT and Mermaid source files were generated.</em></p>"
    )
    current_svg = getattr(diagram, "svg_path", None) if diagram is not None else None
    if (
        diagram is not None
        and getattr(diagram, "svg_rendered", False)
        and current_svg is not None
        and Path(current_svg).is_file()
        and not Path(current_svg).is_symlink()
    ):
        # Reference (not inline) the SVG generated by THIS run; scripts in
        # SVG do not execute when loaded via <img>.
        svg_html = (
            '<figure class="diagram">'
            f'<img src="{html.escape(Path(current_svg).name)}" '
            'alt="Network data-flow diagram" '
            'style="max-width:100%;height:auto"></figure>'
        )
    if diagram is not None and getattr(diagram, "render_error", None):
        svg_html += (
            f"<p><em>{html.escape(str(diagram.render_error))}</em></p>"
        )

    exec_summary = (
        f"<p>The scan parsed <strong>{len(hosts)}</strong> "
        f"{plural('host', len(hosts))} with <strong>{len(open_services)}"
        f"</strong> open {plural('service', len(open_services))}, producing "
        f"<strong>{len(inbound)}</strong> candidate inbound and "
        f"<strong>{len(outbound)}</strong> candidate outbound firewall "
        f"{plural('exception', len(inbound) + len(outbound))}. "
        f"<strong>{len(reviews)}</strong> {plural('item', len(reviews))} "
        f"{verb(len(reviews), 'requires', 'require')} manual review and "
        f"<strong>{len(high)}</strong> exposed "
        f"{plural('service', len(high))} {were(len(high))} rated High or "
        "Critical. All rules are proposals scoped to the evidence; none "
        "should be implemented without the validation steps in the "
        "Methodology section.</p>"
    )
    methodology = (
        "<p>Flows classified <em>Observed</em> are directly supported by an "
        "open port in the Nmap XML and prove reachability from the scanner's "
        "location only. <em>Inferred</em> flows are derived from detected "
        "services, host roles, or common protocol behavior and are unverified. "
        "<em>User-Defined</em> flows come from the YAML configuration. "
        "<em>Manual Review Required</em> marks results that could produce an "
        "unsafe or overly broad rule. Before implementing any exception, "
        "validate it against firewall logs, NetFlow/sFlow, packet capture, "
        "Zeek, or SIEM data, and confirm ownership and business purpose with "
        "the system owner.</p>"
    )
    if zeek is not None:
        methodology += (
            "<p>Zeek-derived rows describe traffic the passive sensor "
            "actually observed. Only successful connections can support a "
            "candidate rule; failed, rejected, unanswered, one-way, and "
            "partial traffic never does. Nmap scanner traffic seen by the "
            "sensor is marked and excluded from production-dependency rules. "
            "Observed traffic does not independently establish business "
            "authorization.</p>"
        )
    limitations = (
        "<p>Nmap XML does not contain a complete record of communications "
        "between systems: it cannot see host-to-host traffic that does not "
        "involve the scanner, asynchronous or scheduled dependencies, or "
        "traffic blocked between other zones. UDP results are frequently "
        "ambiguous (open|filtered). Service and OS detection are heuristics. "
        "Version-based findings are not confirmed vulnerabilities.</p>"
    )
    if zeek is not None:
        limitations += (
            "<p>Zeek can only describe traffic visible to its sensor during "
            "the collection window: mirrored VLANs it does not see, "
            "same-host or intra-virtual-switch traffic, and encrypted "
            "payloads are all outside its view. A dependency that produced "
            "no traffic during the window is not proven unnecessary.</p>"
        )
    assumptions_html = "<ul>" + "".join(
        f"<li>{html.escape(a)}</li>" for a in assumptions
    ) + "</ul>"
    meta_html = (
        "<ul>"
        f"<li>Command line: <code>{html.escape(metadata.command_line or 'unknown')}</code></li>"
        f"<li>Nmap version: {html.escape(metadata.nmap_version or 'unknown')}</li>"
        f"<li>Started: {html.escape(metadata.start_time or 'unknown')}; "
        f"finished: {html.escape(metadata.end_time or 'unknown')} "
        f"({html.escape(metadata.summary or 'no summary')})</li>"
        f"<li>Scan types: {html.escape(', '.join(metadata.scan_types) or 'unknown')}</li>"
        f"<li>Source file: {html.escape(metadata.source_file)}</li>"
        "</ul>"
    )

    zeek_sections_pre: List[str] = []
    zeek_sections_mid: List[str] = []
    zeek_sections_post: List[str] = []
    if zeek is not None:
        successful_aggs = [a for a in zeek.aggregates if a.successful_count]
        failed_aggs = [
            a for a in zeek.aggregates
            if (a.failed_count + a.rejected_count) and not a.successful_count
        ]
        from .zeek_correlation import (
            count_communications, evidence_overlap_breakdown,
            is_scanner_observation, supported_by_nmap_and_zeek,
        )

        # Issue 3 (v1.2.2): corroboration is an evidence-overlap question -
        # a flow supported by BOTH nmap and zeek in its evidence_sources -
        # not a single primary-status match. A three-source declared flow
        # keeps its user-defined-and-zeek status and still counts here.
        both_flows = [f for f in flows if supported_by_nmap_and_zeek(f)]
        overlap = evidence_overlap_breakdown(flows)
        corroborated = both_flows
        scanner_audit_flows = [
            f for f in flows if is_scanner_observation(f)
        ]
        declared_observed = [
            f for f in flows if f.correlation_status == "user-defined-and-zeek"
        ]
        zeek_only_flows = [
            f for f in flows
            if f.correlation_status in ("zeek-traffic-only", "conflicting-evidence")
        ]
        unobserved_services = [
            s for s in services
            if s.state == "open" and s.zeek_observation.startswith("Not observed")
        ]
        scanner_only_services = [
            s for s in services
            if s.state == "open" and s.scanner_only_zeek_traffic_observed
        ]
        corroborated_services = [
            s for s in services
            if s.state == "open" and s.non_scanner_zeek_traffic_observed
        ]
        # Defect 6: communications are counted by identity, perspectives
        # separately, so one dependency is never reported as two.
        corroborated_comms = overlap["supported_by_nmap_and_zeek"]
        declared_comms = count_communications(declared_observed)
        zeek_only_comms = count_communications(zeek_only_flows)
        zeek_endpoint_count = sum(
            1 for e in zeek.endpoints
            if "Zeek" in e.observation_source or e.observation_source == "External"
        )
        scanner_audit_comms = count_communications(scanner_audit_flows)
        ext_count = len(zeek.external_dependencies)
        exec_summary = (
            f"<p>Nmap parsed <strong>{len(hosts)}</strong> scanned "
            f"{plural('host', len(hosts))} with <strong>{len(open_services)}"
            f"</strong> open {plural('service', len(open_services))}. The Zeek "
            f"sensor observed <strong>{len(zeek.endpoints)}</strong> "
            f"{plural('endpoint', len(zeek.endpoints))} ({zeek_endpoint_count} "
            f"seen by Zeek) across <strong>{len(zeek.aggregates)}</strong> "
            f"aggregated {plural('flow', len(zeek.aggregates))}: "
            f"<strong>{len(successful_aggs)}</strong> with successful "
            f"connections and <strong>{len(failed_aggs)}</strong> only failed "
            f"or rejected. <strong>{corroborated_comms}</strong> unique "
            f"{plural('communication', corroborated_comms)} "
            f"({len(corroborated)} firewall "
            f"{plural('perspective', len(corroborated))}) "
            f"{verb(corroborated_comms, 'is', 'are')} supported by both Nmap "
            f"and Zeek (evidence from both tools, whatever the primary "
            f"correlation status: {overlap['nmap_and_zeek_only']} "
            f"Nmap-and-Zeek, {overlap['declared_with_nmap_corroboration']} "
            f"declared with Nmap corroboration, "
            f"{overlap['inferred_with_nmap_corroboration']} inferred with "
            f"Nmap corroboration), and <strong>{zeek_only_comms}</strong> "
            f"unique {plural('communication', zeek_only_comms)} "
            f"({len(zeek_only_flows)} firewall "
            f"{plural('perspective', len(zeek_only_flows))}) "
            f"{were(zeek_only_comms)} seen only by Zeek. Of the Nmap-exposed "
            f"services, <strong>{len(corroborated_services)}</strong> carried "
            f"non-scanner production traffic, "
            f"<strong>{len(scanner_only_services)}</strong> "
            f"{were(len(scanner_only_services))} observed only in "
            f"scanner-generated traffic, and "
            f"<strong>{len(unobserved_services)}</strong> had no Zeek traffic "
            f"at all during the collection window (none of which means they "
            f"are unused). A further <strong>{scanner_audit_comms}</strong> "
            f"{plural('communication', scanner_audit_comms)} "
            f"{were(scanner_audit_comms)} the scanner's own probes, counted "
            f"as scan-audit evidence rather than production traffic. "
            f"<strong>{ext_count}</strong> external "
            f"{plural('dependency', ext_count)} {were(ext_count)} identified. "
            f"Sensor health: <strong>{html.escape(zeek.health.status)}</strong>"
            f". The analysis produced <strong>{len(inbound)}</strong> "
            f"candidate inbound and <strong>{len(outbound)}</strong> candidate "
            f"outbound firewall "
            f"{plural('exception', len(inbound) + len(outbound))}, with "
            f"<strong>{len(reviews)}</strong> manual-review "
            f"{plural('item', len(reviews))}. All rules are proposals scoped "
            f"to the evidence.</p>"
        )
        meta = zeek.metadata
        sources_html = (
            "<ul>"
            f"<li>Nmap XML: <code>{html.escape(metadata.source_file)}</code>; "
            f"scan started {html.escape(metadata.start_time or 'unknown')}</li>"
            f"<li>Zeek input directories: "
            f"{html.escape(', '.join(meta.input_directories) or 'none')}</li>"
            f"<li>Zeek files processed: {len(meta.files_processed)} "
            f"({html.escape(', '.join(sorted(meta.log_types_found)) or 'none')})</li>"
            f"<li>Zeek observation window: "
            f"{html.escape(meta.earliest_timestamp or 'unknown')} to "
            f"{html.escape(meta.latest_timestamp or 'unknown')} (UTC)</li>"
            f"<li>conn.log records: {meta.record_counts.get('conn', 0)}; "
            f"malformed records (all logs): "
            f"{sum(meta.malformed_counts.values())}</li>"
            "</ul>"
            "<p><em>Nmap describes reachability from the scanner; Zeek "
            "describes traffic actually seen by its sensor; configuration "
            "describes declared intent. These are correlated, never "
            "conflated.</em></p>"
        )
        health_html = (
            "<ul>"
            f"<li>Status: <strong>{html.escape(zeek.health.status)}</strong></li>"
            f"<li>Capture-loss data available: "
            f"{'yes' if zeek.health.capture_loss_available else 'no (health cannot be assumed healthy)'}</li>"
            f"<li>Maximum capture loss: "
            f"{zeek.health.max_capture_loss_percent:.2f}%</li>"
            f"<li>Aggregates with missed bytes: "
            f"{zeek.health.aggregates_with_missed_bytes} "
            f"({zeek.health.total_missed_bytes} "
            f"{plural('byte', zeek.health.total_missed_bytes)} total)</li>"
            f"<li>Reporter errors/warnings: {len(zeek.health.reporter_errors)}"
            f"/{len(zeek.health.reporter_warnings)}</li>"
            f"<li>Malformed input records: {zeek.health.malformed_records}</li>"
            "</ul><ul>"
            + "".join(f"<li>{html.escape(n)}</li>" for n in zeek.health.notes)
            + "</ul>"
        )
        agg_cols = [
            ("originator", "Originator"), ("responder", "Responder"),
            ("protocol", "Proto"), ("responder_port", "Port"),
            ("outcome_label", "Outcome"), ("services", "Zeek services"),
            ("connection_count", "Conns"), ("successful_count", "OK"),
            ("failed_count", "Failed"), ("rejected_count", "Rejected"),
            ("one_way_count", "One-way"), ("first_seen", "First seen"),
            ("last_seen", "Last seen"), ("originator_bytes", "Orig bytes"),
            ("responder_bytes", "Resp bytes"),
            ("conn_states", "States"), ("scanner_traffic", "Scanner"),
            ("sensor_quality", "Sensor"),
            ("tls_server_names", "TLS names"), ("dns_names", "DNS names"),
        ]
        endpoint_cols = [
            ("ip", "IP"), ("display_name", "Display name"),
            ("device_hostname_source", "Name source"), ("zone", "Zone"),
            ("observation_source", "Observed by"),
            ("dns_aliases", "DNS aliases"), ("dhcp_hostname", "DHCP name"),
            ("http_hosts", "HTTP hosts"), ("tls_server_names", "TLS names"),
            ("certificate_identities", "Certificates"),
            ("first_seen", "First seen"), ("last_seen", "Last seen"),
        ]
        finding_cols = [
            ("finding_id", "ID"), ("category", "Category"),
            ("source", "Source"), ("destination", "Destination"),
            ("protocol", "Proto"), ("port", "Port"), ("detail", "Detail"),
            ("evidence", "Evidence"), ("recommendation", "Recommendation"),
            ("correlation_status", "Correlation"),
        ]
        zflow_cols = flow_cols + [
            ("correlation_status", "Correlation"),
            ("evidence_sources", "Evidence sources"),
            ("zeek_observation", "Zeek observation"),
            ("connection_count", "Conns"),
            ("successful_connections", "OK"),
            ("failed_connections", "Failed"),
            ("first_seen", "First seen"), ("last_seen", "Last seen"),
        ]
        enrichment_rows = [
            as_flat_dict(e) for e in zeek.endpoints
            if e.dns_aliases or e.http_hosts or e.tls_server_names
            or e.certificate_identities or e.dhcp_hostname
        ]
        zeek_sections_pre = [
            _section("Data sources and observation windows", None, sources_html),
            _section("Zeek sensor health", None, health_html),
        ]
        zeek_sections_mid = [
            _section(
                "Unified endpoint inventory", len(zeek.endpoints),
                _table([as_flat_dict(e) for e in zeek.endpoints],
                       endpoint_cols, "t-zeek-endpoints"),
                note="Scanned hosts and passively observed endpoints are "
                     "distinguished by the 'Observed by' column; Zeek-only "
                     "endpoints were never Nmap-scanned.",
            ),
            _section(
                "Zeek-observed communications", len(zeek.aggregates),
                _table([as_flat_dict(a) for a in zeek.aggregates],
                       agg_cols, "t-zeek-flows"),
                note="One row per originator/responder/protocol/port; the "
                     "originator is the initiator. Scanner-generated traffic "
                     "is marked and excluded from production rules.",
            ),
            _section(
                f"Communications supported by both Nmap and Zeek "
                f"({corroborated_comms} unique, {len(corroborated)} firewall "
                f"{plural('perspective', len(corroborated))})",
                corroborated_comms,
                _table([as_flat_dict(f) for f in corroborated],
                       zflow_cols, "t-zeek-corroborated"),
                note="Evidence-source overlap: every row has both nmap and "
                     "zeek in its evidence_sources, whatever its primary "
                     "correlation status. This dimension OVERLAPS with the "
                     "declared-and-observed and inferred-and-observed sections "
                     "below - a declared PostgreSQL dependency Nmap confirmed "
                     "open appears here and there. Rows keep their own "
                     "correlation_status (e.g. user-defined-and-zeek) and full "
                     "evidence_sources.",
            ),
            _section(
                f"Declared and observed communications ({declared_comms} "
                f"unique, {len(declared_observed)} firewall "
                f"{plural('perspective', len(declared_observed))})",
                declared_comms,
                _table([as_flat_dict(f) for f in declared_observed],
                       zflow_cols, "t-zeek-declared"),
                note="Dependencies both declared in configuration and "
                     "observed in traffic.",
            ),
            _section(
                "Nmap-exposed services with no Zeek traffic at all",
                len(unobserved_services),
                _table([as_flat_dict(s) for s in unobserved_services],
                       service_cols + [("zeek_observation", "Zeek observation")],
                       "t-zeek-unobserved"),
                note="Absence of traffic in this window is NOT evidence that "
                     "a service is unused, unneeded, or safe to remove.",
            ),
            _section(
                "Nmap-exposed services observed only in scanner-generated "
                "traffic", len(scanner_only_services),
                _table([as_flat_dict(s) for s in scanner_only_services],
                       service_cols + [("zeek_observation", "Zeek observation")],
                       "t-zeek-scanner-only"),
                note="The only traffic seen to these services came from the "
                     "Nmap scanner itself. That is not production usage and "
                     "never generates a dependency rule - but it is also not "
                     "evidence the service is unused.",
            ),
            _section(
                f"Zeek-observed communications not confirmed by Nmap "
                f"({zeek_only_comms} unique, {len(zeek_only_flows)} firewall "
                f"{plural('perspective', len(zeek_only_flows))})",
                zeek_only_comms,
                _table([as_flat_dict(f) for f in zeek_only_flows],
                       zflow_cols, "t-zeek-only"),
                note="Zeek observed traffic Nmap did not corroborate: the "
                     "destination may be outside scan scope, unscanned, or "
                     "in a different state at scan time. Zeek is not assumed "
                     "wrong; conflicts go to manual review.",
            ),
            _section(
                "Attempted, rejected, and one-way communications",
                len(zeek.attempted),
                _table([as_flat_dict(a) for a in zeek.attempted],
                       agg_cols, "t-zeek-attempted"),
                note="These never become firewall allow rules.",
            ),
            _section(
                "External dependencies", len(zeek.external_dependencies),
                _table([as_flat_dict(a) for a in zeek.external_dependencies],
                       agg_cols, "t-zeek-external"),
                note="Reported separately; external rules are generated only "
                     "when zeek.include_external_dependencies_in_rules is "
                     "enabled, and always with concrete IPs through policy "
                     "review (never automatic FQDN rules).",
            ),
            _section(
                "DNS and application identity enrichment",
                len(enrichment_rows),
                _table(enrichment_rows, endpoint_cols, "t-zeek-enrichment"),
                note="HTTP hosts, TLS server names, and certificate subjects "
                     "identify service endpoints, not necessarily the "
                     "machine itself; they never replace the device hostname.",
            ),
            _section(
                "Correlation discrepancies", len(zeek.findings),
                _table([as_flat_dict(f) for f in zeek.findings],
                       finding_cols, "t-zeek-findings"),
                note="Neutral observations for review; none of these are "
                     "automatically vulnerabilities.",
            ),
        ]

    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sections = [
        _section("Executive summary", None, exec_summary),
        _section("Scan metadata", None, meta_html),
        *zeek_sections_pre,
        _section("Data-flow diagram", None, svg_html),
        *zeek_sections_mid,
        _section(
            "Host inventory",
            len(host_rows),
            _table(
                host_rows,
                [
                    ("hostname", "Hostname"), ("ip", "IP"), ("zone", "Zone"),
                    ("role", "Inferred role"), ("role_source", "Role source"),
                    ("os", "OS guess"), ("mac_vendor", "MAC vendor"),
                    ("state", "State"), ("open_ports", "Open ports"),
                    ("owner", "Owner"), ("purpose", "Purpose"),
                ],
                "t-hosts",
            ),
        ),
        _section(
            "Service inventory",
            len(services),
            _table([as_flat_dict(s) for s in services], service_cols, "t-services"),
        ),
        _section(
            "High-risk findings",
            len(high),
            _table(
                [as_flat_dict(s) for s in high],
                service_cols + [("risk_reasons", "Reasons")],
                "t-high",
            ),
        ),
        _section(
            "Observed flows",
            len(observed),
            _table([as_flat_dict(f) for f in observed], flow_cols, "t-observed"),
            note="Reachability from the scanner's location only.",
        ),
        _section(
            "Inferred flows",
            len(inferred),
            _table([as_flat_dict(f) for f in inferred], flow_cols, "t-inferred"),
            note="Derived from roles/configuration; unverified until validated.",
        ),
        _section(
            "User-defined and review-flagged flows",
            len(other_flows),
            _table([as_flat_dict(f) for f in other_flows], flow_cols, "t-other-flows"),
        ),
        _section(
            "Inbound firewall exceptions (candidates)",
            len(inbound),
            _table([as_flat_dict(r) for r in inbound], rule_cols, "t-inbound"),
        ),
        _section(
            "Outbound firewall exceptions (candidates)",
            len(outbound),
            _table([as_flat_dict(r) for r in outbound], rule_cols, "t-outbound"),
        ),
        _section(
            "Manual review",
            len(reviews),
            _table([as_flat_dict(m) for m in reviews], review_cols, "t-review"),
        ),
        _section(
            "NSE vulnerability findings (as reported)",
            len(vulns),
            _table([as_flat_dict(v) for v in vulns], vuln_cols, "t-vulns"),
            note="Categories reflect script output only; nothing here is "
            "independently confirmed by this tool.",
        ),
        _section(
            "Run status",
            None,
            "<ul>" + "".join(
                f"<li><strong>{html.escape(str(k))}</strong>: {html.escape(str(v))}</li>"
                for k, v in (run_status or {}).items()
            ) + "</ul>" if run_status else "<p><em>Not recorded.</em></p>",
        ),
        _section("Assumptions", None, assumptions_html),
        _section("Methodology and evidence classes", None, methodology),
        _section("Limitations", None, limitations),
    ]

    active_disclaimer = COMBINED_DISCLAIMER if zeek is not None else DISCLAIMER
    report_title = ("Nmap + Zeek Flow Analysis Report" if zeek is not None
                    else "Nmap Flow Analysis Report")
    document = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{report_title}</title>\n<style>{_CSS}</style>\n</head>\n<body>\n"
        f"<header><h1>{report_title}</h1>"
        f'<div class="meta">Generated {generated} &middot; {TOOL_NAME} '
        f"{__version__} &middot; input: {html.escape(metadata.source_file)}</div></header>\n"
        f'<main><div class="disclaimer">{html.escape(active_disclaimer)} {html.escape(PERSPECTIVE_NOTE)}</div>\n'
        + "\n".join(sections)
        + f"\n</main>\n<footer>{html.escape(active_disclaimer)} {html.escape(PERSPECTIVE_NOTE)}</footer>\n"
        f"<script>{_JS}</script>\n</body>\n</html>\n"
    )
    atomic_write_text(path, document)
    LOG.debug("Wrote %s", path.name)


# ---------------------------------------------------------------------------
# Manual review finalization
# ---------------------------------------------------------------------------

def finalize_reviews(reviews: Iterable[ManualReviewItem]) -> List[ManualReviewItem]:
    """Deduplicate, deterministically order, and assign IDs to review items."""
    unique: Dict[Tuple, ManualReviewItem] = {}
    for item in reviews:
        key = (item.category, item.ip, item.protocol, item.port, item.finding)
        unique.setdefault(key, item)
    ordered = sorted(
        unique.values(),
        key=lambda m: (m.category, m.ip, m.protocol, m.port, m.finding),
    )
    for index, item in enumerate(ordered, start=1):
        item.item_id = f"MR-{index:04d}"
    return ordered
