"""Command-line interface and pipeline orchestration."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import List, Optional

from . import TOOL_NAME, __version__
from .config import AnalyzerConfig, ConfigError, default_config, load_config
from .diagrams import write_diagrams
from .excel_export import export_excel
from .firewall_rules import build_inbound, build_outbound
from .flow_analysis import AnalysisOptions, build_flows, enrich_hosts
from .logging_config import close_invocation_logging, setup_logging
from .output_safety import (
    OutputSafetyError,
    safe_remove_stale,
    validate_output_destination,
    validate_output_directory,
)
from .reports import atomic_write_text, write_json_object
from .models import EvidenceClass, FirewallRule, Flow, ManualReviewItem
from .parser import ParserError, parse_nmap_xml
from .reports import (
    build_assumptions,
    finalize_reviews,
    write_csv,
    write_findings_summary,
    write_html_report,
    write_json,
    write_normalized_data,
)
from .zeek_aggregation import load_zeek
from .pluralize import count_noun, plural
from .zeek_correlation import (
    ZeekReportData, correlate_zeek, count_communications,
    evidence_overlap_breakdown, is_scanner_observation, supported_by_nmap_and_zeek,
)
from .zeek_models import CorrelationFinding, ZeekFlowAggregate
from .flow_analysis import sort_and_assign_flow_ids
from .risk_analysis import build_service_records, collect_vuln_findings
from .models import ServiceRecord
from .runtime import configure_bundled_graphviz


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nmap_flow_analyzer",
        description=(
            "Parse an Nmap XML report into a data-flow diagram, candidate "
            "inbound/outbound firewall exception lists, a service inventory, "
            "and a manual-review report. Every flow and rule carries an "
            "evidence classification (Observed / Inferred / User-Defined / "
            "Unknown / Manual Review Required)."
        ),
    )
    parser.add_argument("--input", required=False, type=Path,
                        help="Nmap XML report (e.g. full-scan.xml)")
    parser.add_argument("--config", type=Path, default=None,
                        help="Optional YAML configuration file")
    parser.add_argument("--output-dir", type=Path, default=Path("./nmap_analysis"),
                        help="Directory for generated reports (default: ./nmap_analysis)")
    parser.add_argument("--scanner-ip", default=None,
                        help="IP address the scan originated from (overrides config)")
    parser.add_argument("--scanner-zone", default=None,
                        help="Security zone of the scanner (overrides config)")
    parser.add_argument("--diagram-detail", choices=["summary", "full"],
                        default="summary",
                        help="summary groups similar services; full shows every "
                             "protocol/port combination")
    parser.add_argument("--include-open-filtered", action="store_true",
                        help="Include open|filtered ports as 'Manual Review "
                             "Required' flows (never as rules)")
    parser.add_argument("--include-inferred-outbound", action="store_true",
                        help="Generate Inferred outbound dependency flows to "
                             "configured infrastructure servers")
    parser.add_argument("--firewall-mode", choices=["stateful", "stateless"],
                        default=None,
                        help="Overrides firewall_mode from the configuration "
                             "(default: stateful)")
    parser.add_argument("--excel", action="store_true",
                        help="Also write firewall_exceptions.xlsx (requires openpyxl)")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose console logging")
    parser.add_argument("--overwrite", action="store_true",
                        help="Allow replacing previously generated reports in "
                             "the output directory. Without it, an output "
                             "directory that already holds generated reports "
                             "is refused (unrelated files never block a run "
                             "and are never touched).")
    parser.add_argument("--graphviz-timeout", type=int, default=60,
                        metavar="SECONDS",
                        help="Maximum seconds to wait for Graphviz rendering "
                             "(default: 60). On timeout the .dot/.mmd sources "
                             "are kept.")
    parser.add_argument("--no-spreadsheet-sanitization", action="store_true",
                        help="Disable CSV/Excel formula-injection protection. "
                             "NOT recommended: only for pipelines that "
                             "post-process raw values and understand the risk.")
    parser.add_argument("--strict", action="store_true",
                        help="Move overly broad or ambiguous rules to manual "
                             "review instead of the exception lists")
    parser.add_argument("--zeek-dir", type=Path, action="append", default=None,
                        help="Optional directory containing Zeek logs (may be "
                             "given more than once); enables Nmap+Zeek "
                             "correlation. Nmap-only behavior is unchanged "
                             "when absent")
    parser.add_argument("--zeek-format", choices=["auto", "json", "tsv"],
                        default="auto",
                        help="Zeek log format (default: auto-detect per file; "
                             "mixed directories are supported)")
    parser.add_argument("--zeek-required", action="store_true",
                        help="Treat missing or unusable Zeek conn.log data as "
                             "a fatal error instead of continuing Nmap-only")
    parser.add_argument("--pcap", type=Path, action="append", default=None,
                        help="Bounded classic PCAP input (may be repeated)")
    parser.add_argument("--pcapng", type=Path, action="append", default=None,
                        help="Bounded PCAPNG input (may be repeated)")
    parser.add_argument("--suricata-eve", type=Path, action="append", default=None,
                        help="Bounded Suricata EVE JSONL input (may be repeated)")
    parser.add_argument("--suricata-rules", type=Path, action="append", default=None,
                        help="Optional bounded Suricata rule metadata input")
    parser.add_argument("--packet-metadata-only", action="store_true", default=True,
                        help="Retain packet metadata only (the safe default)")
    parser.add_argument("--packet-payload-limit", type=int, default=0,
                        help="Maximum normalized payload bytes; currently must remain 0")
    parser.add_argument("--flow-table-limit", type=int, default=100_000,
                        help="Maximum active native-capture flows")
    parser.add_argument("--ingestion-strict", action="store_true",
                        help="Stop the selected adapter on the first malformed record")
    parser.add_argument("--no-preflight", action="store_true",
                        help="Explicitly suppress startup preflight checks")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Run without prompts (normal analysis is already prompt-free)")
    parser.add_argument("--export-shadow-evidence", action="store_true",
                        help="Also export a Core-validated .shadowevidence.zip package")
    parser.add_argument("--shadow-case-id",
                        help="Stable case identifier used for Shadow Evidence export")
    parser.add_argument("--shadow-case-title",
                        help="Human-readable Shadow Evidence case title")
    parser.add_argument("--import-shadow-evidence", type=Path,
                        help="Validate and safely import a .shadowevidence.zip into --output-dir")
    parser.add_argument("--verify-shadow-evidence", type=Path,
                        help="Validate a .shadowevidence.zip without importing it")
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {__version__}")
    return parser


def _run_streaming_adapters(args: argparse.Namespace, staging: Path) -> dict[str, object]:
    from shadow_core.ingestion import AdapterContext, EvidenceSource, ResourceBudget
    from shadow_core.hashing import sha256_file
    from shadow_core.identifiers import stable_identifier

    from .ingestion import PcapAdapter, PcapngAdapter, SuricataEveAdapter, parse_suricata_rules

    if args.packet_payload_limit != 0:
        raise ValueError("packet payload normalization is not enabled in this milestone")
    if args.flow_table_limit <= 0:
        raise ValueError("--flow-table-limit must be positive")
    budget = ResourceBudget(max_active_flows=args.flow_table_limit)
    context = AdapterContext(budget=budget, strict=args.ingestion_strict)
    results: list[dict[str, object]] = []
    records: list[dict[str, object]] = []
    inputs = [
        *((path, PcapAdapter) for path in (args.pcap or [])),
        *((path, PcapngAdapter) for path in (args.pcapng or [])),
        *((path, SuricataEveAdapter) for path in (args.suricata_eve or [])),
    ]
    captures = [*(args.pcap or []), *(args.pcapng or [])]
    shared_capture_source = (
        stable_identifier("source", {"sha256": sha256_file(captures[0])})
        if len(captures) == 1 else None
    )
    for path, adapter_type in inputs:
        adapter = adapter_type()
        parent = shared_capture_source if adapter.name in {"pcap", "pcapng", "suricata-eve"} else None
        source = EvidenceSource(path, parent_evidence_id=parent)
        probe = adapter.probe(source, context)
        if not probe.magic_matched:
            raise ValueError(f"{path}: content does not match {adapter.name}")
        streamed = list(adapter.records(source, context))
        records.extend({
            "id": record.id, "record_type": record.record_type,
            "observed_at": record.observed_at, "data": record.data,
            "raw_sha256": record.raw_sha256,
            "independent_source_id": record.independent_source_id,
            "analysis_perspective": record.analysis_perspective,
            "location": dataclasses.asdict(record.location),
        } for record in streamed)
        results.append({
            "path": path.name, "adapter": adapter.name,
            "probe": dataclasses.asdict(probe),
            "summary": dataclasses.asdict(adapter.summary) if adapter.summary else None,
            "diagnostics": [dataclasses.asdict(item) for item in adapter.diagnostics],
        })
    rule_metadata = [record for path in (args.suricata_rules or []) for record in parse_suricata_rules(path)]
    value: dict[str, object] = {"adapters": results, "records": records, "suricata_rule_metadata": rule_metadata}
    atomic_write_text(staging / "ingestion_summary.json", json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")
    return value


def _apply_cli_overrides(
    config: AnalyzerConfig, args: argparse.Namespace, log: logging.Logger
) -> Optional[str]:
    """Apply CLI overrides; returns an error message or None."""
    if args.scanner_ip:
        try:
            ipaddress.ip_address(args.scanner_ip)
        except ValueError:
            return f"--scanner-ip is not a valid IP address: {args.scanner_ip!r}"
        config.scanner_ip = args.scanner_ip
    if args.scanner_zone:
        config.scanner_zone = args.scanner_zone
        if config.zones and args.scanner_zone not in config.zones:
            log.warning(
                "Scanner zone %r is not defined under zones: in the "
                "configuration; zone CIDRs cannot be resolved for it",
                args.scanner_zone,
            )
    if args.firewall_mode:
        config.firewall_mode = args.firewall_mode
    return None


#: Files this tool generates; the overwrite policy checks exactly these and
#: never touches anything else in the output directory.
GENERATED_FILES = [
    "service_inventory.csv", "service_inventory.json",
    "inbound_exceptions.csv", "inbound_exceptions.json",
    "outbound_exceptions.csv", "outbound_exceptions.json",
    "manual_review.csv", "findings_summary.md", "normalized_data.json",
    "analysis_report.html", "data_flow_diagram.dot", "data_flow_diagram.mmd",
    "data_flow_diagram.svg", "data_flow_diagram.png",
    "firewall_exceptions.xlsx", "execution.log", "run_manifest.json",
    # v1.2.0 Zeek artifacts (generated only when --zeek-dir is supplied,
    # but always eligible for stale cleanup and collision checks)
    "zeek_observed_flows.csv", "zeek_observed_flows.json",
    "correlation_findings.csv", "correlation_findings.json",
    "external_dependencies.csv", "external_dependencies.json",
    "zeek_input_summary.json",
]


def check_output_dir(output_dir: Path, overwrite: bool) -> Optional[str]:
    """Refuse to silently replace previously generated reports.

    Returns an error message when the directory already contains files this
    tool generates and --overwrite was not given.  Unrelated files never
    block the run and are never modified or deleted.
    """
    if not output_dir.exists() or overwrite:
        return None
    existing = [name for name in GENERATED_FILES if (output_dir / name).exists()]
    if not existing:
        return None
    return (
        f"Output directory {output_dir} already contains generated reports "
        f"({', '.join(existing[:4])}{', ...' if len(existing) > 4 else ''}). "
        "Re-run with --overwrite to replace them, or choose a new "
        "--output-dir. Unrelated files are never touched either way."
    )


from dataclasses import dataclass, field


@dataclass
class RunContext:
    """Tracks exactly what THIS execution produced."""

    run_id: str
    started_at: datetime.datetime
    output_dir: Path
    staging_dir: Path
    overwrite: bool
    spreadsheet_sanitization: bool
    excel_requested: bool
    generated_artifacts: dict = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def register(self, path: Path) -> None:
        self.generated_artifacts[path.name] = path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_previous_manifest(output_dir: Path, log: logging.Logger) -> List[str]:
    """Basenames of files a previous run generated, per its manifest.

    A missing or corrupt manifest is handled safely: cleanup then relies on
    the legacy allowlist only.
    """
    manifest_path = output_dir / "run_manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return []
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        names = []
        for entry in data.get("generated_files", []):
            name = Path(str(entry.get("path", ""))).name  # basename only
            if name:
                names.append(name)
        return names
    except (OSError, ValueError) as exc:
        log.warning("Previous run_manifest.json unreadable (%s); using legacy "
                    "allowlist only for stale cleanup", exc)
        return []


def _write_manifest(ctx: RunContext, staging: Path, args, metadata,
                    diagram, excel_generated: bool,
                    zeek_analysis=None, zeek_active: bool = False) -> None:
    files = []
    for entry in sorted(staging.iterdir()):
        if entry.name == "run_manifest.json" or not entry.is_file():
            continue
        files.append({
            "path": entry.name,
            "size": entry.stat().st_size,
            "sha256": _sha256(entry),
        })
    manifest = {
        "application": TOOL_NAME,
        "version": __version__,
        "run_id": ctx.run_id,
        "started_at": ctx.started_at.isoformat(timespec="seconds"),
        "completed_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "input_file": str(args.input),
        "generated_files": files,
        "graphviz": {
            "available": diagram.graphviz_available,
            "svg_rendered": diagram.svg_rendered,
            "png_rendered": diagram.png_rendered,
            "error": diagram.render_error,
        },
        "excel_requested": ctx.excel_requested,
        "excel_generated": excel_generated,
        "spreadsheet_sanitization": ctx.spreadsheet_sanitization,
        # v1.2.0 Zeek provenance (never includes secrets or full HTTP URIs)
        "zeek": {
            "requested": bool(args.zeek_dir),
            "active": zeek_active,
            "input_directories": (
                zeek_analysis.metadata.input_directories
                if zeek_analysis else []
            ),
            "files_processed": (
                zeek_analysis.metadata.files_processed if zeek_analysis else []
            ),
            "log_types_found": (
                zeek_analysis.metadata.log_types_found if zeek_analysis else []
            ),
            "record_counts": (
                zeek_analysis.metadata.record_counts if zeek_analysis else {}
            ),
            "malformed_record_counts": (
                zeek_analysis.metadata.malformed_counts if zeek_analysis else {}
            ),
            "log_type_summaries": (
                zeek_analysis.metadata.log_type_summaries
                if zeek_analysis else []
            ),
            "raw_records_read": (
                zeek_analysis.metadata.raw_records_read if zeek_analysis else {}
            ),
            "usable_records": (
                zeek_analysis.metadata.usable_records if zeek_analysis else {}
            ),
            "earliest_timestamp": (
                zeek_analysis.metadata.earliest_timestamp
                if zeek_analysis else ""
            ),
            "latest_timestamp": (
                zeek_analysis.metadata.latest_timestamp
                if zeek_analysis else ""
            ),
            "sensor_health": (
                zeek_analysis.health.status if zeek_analysis else "n/a"
            ),
            "artifacts_generated": zeek_active,
            "warnings": (
                zeek_analysis.metadata.warnings if zeek_analysis else []
            ),
        },
    }
    atomic_write_text(
        staging / "run_manifest.json",
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    )


def _main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    output_dir: Path = args.output_dir
    if args.verify_shadow_evidence:
        from .shadow_evidence import verify_shadow_evidence

        result = verify_shadow_evidence(args.verify_shadow_evidence)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["valid"] else 2
    if args.import_shadow_evidence:
        from .shadow_evidence import import_shadow_evidence

        try:
            imported = import_shadow_evidence(args.import_shadow_evidence, output_dir)
        except Exception as exc:
            print(f"error: Shadow Evidence import failed: {exc}", file=sys.stderr)
            return 2
        print(f"Shadow Evidence imported to: {imported}")
        return 0
    if args.input is None:
        print("error: --input is required unless importing or verifying Shadow Evidence", file=sys.stderr)
        return 2
    if args.export_shadow_evidence and not args.shadow_case_id:
        print("error: --shadow-case-id is required with --export-shadow-evidence", file=sys.stderr)
        return 2
    refusal = check_output_dir(output_dir, args.overwrite)
    if refusal:
        print(f"error: {refusal}", file=sys.stderr)
        return 2
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        root = validate_output_directory(output_dir)
        # execution.log streams during the run and is the one non-staged,
        # non-atomic output (documented limitation); validate it up front so
        # a symlinked log entry can never redirect writes elsewhere.
        validate_output_destination(root, root / "execution.log")
    except (OSError, OutputSafetyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    log = setup_logging(root, verbose=args.verbose)
    log.info("%s %s starting", TOOL_NAME, __version__)

    # -- configuration ------------------------------------------------------
    try:
        config = load_config(args.config) if args.config else default_config()
    except ConfigError as exc:
        log.error("%s", exc)
        return 2
    error = _apply_cli_overrides(config, args, log)
    if error:
        log.error("%s", error)
        return 2
    options = AnalysisOptions(
        include_open_filtered=args.include_open_filtered,
        include_inferred_outbound=args.include_inferred_outbound,
        firewall_mode=config.firewall_mode,
        strict=args.strict,
        diagram_detail=args.diagram_detail,
    )

    # -- parse --------------------------------------------------------------
    try:
        metadata, hosts = parse_nmap_xml(args.input)
    except ParserError as exc:
        log.error("%s", exc)
        return 2

    # -- analyze ------------------------------------------------------------
    enrich_hosts(hosts, config)
    service_records: List[ServiceRecord] = build_service_records(hosts, config)
    flow_result = build_flows(hosts, service_records, config, options)
    flows: List[Flow] = flow_result.flows
    reviews: List[ManualReviewItem] = list(flow_result.reviews)

    # -- optional Zeek ingestion and correlation ----------------------------
    zeek_analysis = None
    zeek_corr = None
    zeek_active = False
    zeek_dirs = list(args.zeek_dir or [])
    if zeek_dirs:
        log.info("Loading Zeek logs from %s",
                 count_noun(len(zeek_dirs), "directory"))
        zeek_analysis = load_zeek(zeek_dirs, args.zeek_format, config,
                                  scanner_ip=config.scanner_ip)
        for warning in zeek_analysis.metadata.warnings:
            log.warning("Zeek input: %s", warning)
        for error in zeek_analysis.metadata.parse_errors[:20]:
            log.warning("Zeek parse: %s", error)
        if not zeek_analysis.metadata.conn_log_available:
            message = ("Zeek analysis requested but no usable conn.log data "
                       "was found in the supplied directories")
            if args.zeek_required:
                log.error("%s (--zeek-required)", message)
                return 2
            log.warning("%s; continuing with Nmap-only analysis", message)
        else:
            zeek_active = True
            zeek_corr = correlate_zeek(hosts, service_records, flows, config,
                                       options, zeek_analysis)
            flows = sort_and_assign_flow_ids(zeek_corr.flows)
            reviews.extend(zeek_corr.reviews)
            log.info(
                "Zeek: %s, %s, %s, sensor health %s",
                count_noun(len(zeek_analysis.aggregates), "aggregated flow"),
                count_noun(len(zeek_corr.findings), "correlation finding"),
                count_noun(len(zeek_corr.external_dependencies),
                           "external dependency"),
                zeek_analysis.health.status,
            )
    zeek_report = None
    if zeek_active:
        zeek_report = ZeekReportData(
            metadata=zeek_analysis.metadata,
            health=zeek_analysis.health,
            aggregates=zeek_analysis.aggregates,
            endpoints=zeek_corr.endpoints,
            findings=zeek_corr.findings,
            external_dependencies=zeek_corr.external_dependencies,
            attempted=zeek_corr.attempted,
        )

    inbound, inbound_reviews = build_inbound(flows, config, options)
    reviews.extend(inbound_reviews)
    outbound, outbound_reviews = build_outbound(flows, inbound, config, options)
    reviews.extend(outbound_reviews)
    reviews = finalize_reviews(reviews)
    vulns = collect_vuln_findings(hosts)
    assumptions = build_assumptions(config, options)
    sanitize = not args.no_spreadsheet_sanitization
    if not sanitize:
        log.warning(
            "Spreadsheet formula-injection protection is DISABLED "
            "(--no-spreadsheet-sanitization); CSV/Excel cells will contain "
            "raw untrusted values"
        )

    # -- staged output generation -------------------------------------------
    ctx = RunContext(
        run_id=uuid.uuid4().hex[:12],
        started_at=datetime.datetime.now(),
        output_dir=root,
        staging_dir=root / f".nmap-flow-analyzer-stage-{uuid.uuid4().hex[:12]}",
        overwrite=args.overwrite,
        spreadsheet_sanitization=sanitize,
        excel_requested=args.excel,
    )
    previous_generated = _read_previous_manifest(root, log)
    excel_message: Optional[str] = None
    excel_generated = False
    try:
        ctx.staging_dir.mkdir(mode=0o700)
    except OSError as exc:
        log.error("Cannot create staging directory: %s", exc)
        return 2

    try:
        staging = ctx.staging_dir
        if args.pcap or args.pcapng or args.suricata_eve or args.suricata_rules:
            _run_streaming_adapters(args, staging)
        write_csv(staging / "service_inventory.csv", service_records,
                  ServiceRecord, sanitize=sanitize)
        write_json(staging / "service_inventory.json", service_records)
        write_csv(staging / "inbound_exceptions.csv", inbound, FirewallRule,
                  sanitize=sanitize)
        write_json(staging / "inbound_exceptions.json", inbound)
        write_csv(staging / "outbound_exceptions.csv", outbound, FirewallRule,
                  sanitize=sanitize)
        write_json(staging / "outbound_exceptions.json", outbound)
        write_csv(staging / "manual_review.csv", reviews, ManualReviewItem,
                  sanitize=sanitize)
        if zeek_report is not None:
            write_csv(staging / "zeek_observed_flows.csv",
                      zeek_report.aggregates, ZeekFlowAggregate,
                      sanitize=sanitize)
            write_json(staging / "zeek_observed_flows.json",
                       zeek_report.aggregates)
            write_csv(staging / "correlation_findings.csv",
                      zeek_report.findings, CorrelationFinding,
                      sanitize=sanitize)
            write_json(staging / "correlation_findings.json",
                       zeek_report.findings)
            write_csv(staging / "external_dependencies.csv",
                      zeek_report.external_dependencies, ZeekFlowAggregate,
                      sanitize=sanitize)
            write_json(staging / "external_dependencies.json",
                       zeek_report.external_dependencies)
            write_json_object(
                staging / "zeek_input_summary.json",
                {
                    "input_metadata": dataclasses.asdict(zeek_report.metadata),
                    "sensor_health": dataclasses.asdict(zeek_report.health),
                },
            )
        diagram = write_diagrams(
            hosts, flows, metadata, config, staging,
            detail=args.diagram_detail, graphviz_timeout=args.graphviz_timeout,
            zeek_active=zeek_active,
        )
        if args.excel:
            excel_message = export_excel(
                staging / "firewall_exceptions.xlsx", metadata, hosts,
                service_records, flows, inbound, outbound, reviews, vulns,
                assumptions, sanitize=sanitize, run_status=None,
                zeek=zeek_report,
            )
            excel_generated = excel_message is None
        planned_count = (
            7  # csv/json data files
            + (7 if zeek_report is not None else 0)  # zeek artifacts
            + 2  # dot + mmd
            + int(diagram.svg_rendered) + int(diagram.png_rendered)
            + int(excel_generated)
            + 3  # findings_summary.md, normalized_data.json, analysis_report.html
            + 1  # run_manifest.json; optional package is additive metadata
        )
        run_status = {
            "Application version": f"{TOOL_NAME} {__version__}",
            "Run ID": ctx.run_id,
            "Output mode": "staged atomic publication",
            "Overwrite": "enabled" if args.overwrite else "disabled",
            "Spreadsheet sanitization": "applied" if sanitize else
                "DISABLED (--no-spreadsheet-sanitization)",
            "Graphviz available": "yes" if diagram.graphviz_available else "no",
            "Graphviz timeout": f"{args.graphviz_timeout}s",
            "Graphviz rendering": "succeeded" if diagram.rendered else
                (diagram.render_error or "not attempted"),
            "SVG generated this run": "yes" if diagram.svg_rendered else "no",
            "PNG generated this run": "yes" if diagram.png_rendered else "no",
            "Excel requested": "yes" if args.excel else "no",
            "Excel generated this run": "yes" if excel_generated else
                ("no - " + (excel_message or "not requested")),
            "Scanner source": (
                f"known ({config.scanner_ip})" if config.scanner_ip
                else "NOT configured - observed inbound candidates withheld to manual review"
            ),
            "Enforcement model": config.rule_generation.enforcement_model,
            "Firewall mode": config.firewall_mode,
            "Strict mode": "on" if args.strict else "off",
            "Inferred outbound": "enabled" if args.include_inferred_outbound else "disabled",
            "Zeek input": (
                "not requested" if not zeek_dirs else
                (f"{sum(1 for f in zeek_analysis.metadata.files_processed)} "
                 f"{plural('file', sum(1 for _ in zeek_analysis.metadata.files_processed))}, "
                 f"{count_noun(len(zeek_analysis.aggregates), 'aggregated flow')}"
                 if zeek_active else "requested but unusable - Nmap-only run")
            ),
            "Zeek sensor health": (
                zeek_analysis.health.status if zeek_active else "n/a"
            ),
            "Generated artifact count": str(planned_count),
            "Warnings": "; ".join(config.warnings + ctx.warnings) or "none",
        }
        write_findings_summary(
            staging / "findings_summary.md", metadata, hosts, service_records,
            flows, inbound, outbound, reviews, vulns, assumptions,
            run_status=run_status, zeek=zeek_report,
        )
        zeek_sections = None
        if zeek_report is not None:
            zeek_sections = {
                "zeek_input_metadata": dataclasses.asdict(zeek_report.metadata),
                "zeek_sensor_health": dataclasses.asdict(zeek_report.health),
                "zeek_flow_aggregates": [
                    dataclasses.asdict(a) for a in zeek_report.aggregates
                ],
                "endpoint_identities": [
                    dataclasses.asdict(e) for e in zeek_report.endpoints
                ],
                "correlation_findings": [
                    dataclasses.asdict(f) for f in zeek_report.findings
                ],
                "external_dependencies": [
                    dataclasses.asdict(a)
                    for a in zeek_report.external_dependencies
                ],
                # Defect 6: unique communications and firewall perspectives
                # are reported as separate, explicitly labeled numbers.
                "zeek_summary_counts": {
                    "unique_observed_communications": count_communications(
                        [a for a in zeek_report.aggregates
                         if a.successful_count and not a.ignored_by_config]
                    ),
                    # Issue 3 (v1.2.2): corroboration by evidence-source
                    # overlap (both nmap and zeek present), regardless of the
                    # primary correlation status.
                    "unique_communications_supported_by_nmap_and_zeek":
                        evidence_overlap_breakdown(flows)[
                            "supported_by_nmap_and_zeek"],
                    "corroboration_by_evidence_overlap":
                        evidence_overlap_breakdown(flows),
                    # Retained for continuity: communications whose PRIMARY
                    # status is nmap-and-zeek (a subset of the above).
                    "unique_corroborated_communications": count_communications(
                        [f for f in flows
                         if f.correlation_status == "nmap-and-zeek"
                         and not is_scanner_observation(f)]
                    ),
                    "corroborated_firewall_perspectives": sum(
                        1 for f in flows
                        if supported_by_nmap_and_zeek(f)
                    ),
                    "scanner_audit_communications": count_communications(
                        [f for f in flows if is_scanner_observation(f)]
                    ),
                    "unique_zeek_only_communications": count_communications(
                        [f for f in flows
                         if f.correlation_status == "zeek-traffic-only"]
                    ),
                    "zeek_only_firewall_perspectives": sum(
                        1 for f in flows
                        if f.correlation_status == "zeek-traffic-only"
                    ),
                    "unique_conflicting_communications": count_communications(
                        [f for f in flows
                         if f.correlation_status == "conflicting-evidence"]
                    ),
                    "nmap_services_with_production_traffic": sum(
                        1 for s in service_records if s.state == "open"
                        and s.non_scanner_zeek_traffic_observed
                    ),
                    "nmap_services_with_scanner_only_traffic": sum(
                        1 for s in service_records if s.state == "open"
                        and s.scanner_only_zeek_traffic_observed
                    ),
                    "nmap_services_with_no_zeek_traffic": sum(
                        1 for s in service_records if s.state == "open"
                        and not s.any_zeek_traffic_observed
                    ),
                    "total_inbound_candidates": len(inbound),
                    "total_outbound_candidates": len(outbound),
                },
            }
        write_normalized_data(
            staging / "normalized_data.json", metadata, hosts, service_records,
            flows, inbound, outbound, reviews, vulns, assumptions,
            run_status=run_status, extra_sections=zeek_sections,
            zeek=zeek_report,
        )
        write_html_report(
            staging / "analysis_report.html", metadata, hosts, service_records,
            flows, inbound, outbound, reviews, vulns, assumptions,
            run_status=run_status, diagram=diagram, zeek=zeek_report,
        )
        if args.export_shadow_evidence:
            from .shadow_evidence import export_shadow_evidence

            export_shadow_evidence(
                staging,
                args.input,
                zeek_dirs,
                args.shadow_case_id,
                args.shadow_case_title or args.shadow_case_id,
                pcap_paths=args.pcap or (),
                pcapng_paths=args.pcapng or (),
                eve_paths=args.suricata_eve or (),
                rule_paths=args.suricata_rules or (),
            )
        _write_manifest(ctx, staging, args, metadata, diagram, excel_generated,
                        zeek_analysis=zeek_analysis, zeek_active=zeek_active)

        # -- publish (validate everything, then atomically move) -----------
        staged = sorted(
            entry for entry in staging.iterdir()
            if entry.is_file() and not entry.name.startswith(".nfa-tmp-")
        )
        finals = {}
        for entry in staged:
            finals[entry] = validate_output_destination(root, root / entry.name)
        for entry, destination in finals.items():
            os.replace(entry, destination)
            ctx.register(destination)
    except OutputSafetyError as exc:
        log.error("Output safety violation: %s (no reports were replaced; "
                  "previous run left intact)", exc)
        return 2
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Report generation failed: %s (no reports were replaced; "
                  "previous run left intact)", exc)
        return 1
    finally:
        shutil.rmtree(ctx.staging_dir, ignore_errors=True)

    # -- stale-artifact cleanup ---------------------------------------------
    known = set(GENERATED_FILES) | set(previous_generated)
    known -= set(ctx.generated_artifacts)
    known.discard("execution.log")  # currently open for this run's logging
    removed, skipped = [], []
    for name in sorted(known):
        entry = root / Path(name).name
        if not entry.exists() and not entry.is_symlink():
            continue
        problem = safe_remove_stale(root, name)
        if problem is None:
            removed.append(name)
            log.info("Removed stale generated artifact: %s", name)
        else:
            skipped.append(problem)
            ctx.warnings.append(problem)
            log.warning("%s", problem)

    # -- summary ------------------------------------------------------------
    open_count = sum(1 for s in service_records if s.state == "open")
    observed_inbound = sum(
        1 for r in inbound if r.evidence_class == EvidenceClass.OBSERVED.value
    )
    inferred_outbound = sum(
        1 for r in outbound if r.evidence_class == EvidenceClass.INFERRED.value
    )
    print(f"Hosts parsed: {len(hosts)}")
    print(f"Open services: {open_count}")
    print(f"Total inbound candidates: {len(inbound)} "
          f"({observed_inbound} with top-level Observed evidence)")
    print(f"Total outbound candidates: {len(outbound)} "
          f"({inferred_outbound} with top-level Inferred evidence)")
    print(f"Manual-review items: {len(reviews)}")
    if zeek_active:
        successful = sum(
            1 for a in zeek_analysis.aggregates if a.successful_count
        )
        conflicting = count_communications(
            [f for f in flows if f.correlation_status == "conflicting-evidence"]
        )
        scanner_only_services = sum(
            1 for s in service_records
            if s.state == "open" and s.scanner_only_zeek_traffic_observed
        )
        supported_both = evidence_overlap_breakdown(flows)[
            "supported_by_nmap_and_zeek"]
        print(f"Zeek unique communications: {len(zeek_analysis.aggregates)} "
              f"({successful} with successful connections)")
        print(f"Communications supported by both Nmap and Zeek "
              f"(evidence overlap): {supported_both}")
        print(f"Zeek firewall perspectives added: "
              f"{sum(1 for f in flows if 'zeek' in f.evidence_sources)}")
        if conflicting:
            print(f"Conflicting-evidence communications (all rules withheld): "
                  f"{conflicting}")
        if scanner_only_services:
            print(f"Services seen only in scanner-generated traffic: "
                  f"{scanner_only_services}")
        print(f"Zeek correlation findings: {len(zeek_corr.findings)}")
        print(f"Zeek external dependencies: "
              f"{len(zeek_corr.external_dependencies)}")
        print(f"Zeek sensor health: {zeek_analysis.health.status}")
    print(f"Reports written to: {root}")
    print("Generated this run:")
    for name in sorted(ctx.generated_artifacts):
        print(f"- {name}")
    not_generated = []
    if not diagram.svg_rendered:
        not_generated.append(("data_flow_diagram.svg",
                              diagram.render_error or "Graphviz unavailable"))
    if not diagram.png_rendered:
        not_generated.append(("data_flow_diagram.png",
                              diagram.render_error or "Graphviz unavailable"))
    if not excel_generated:
        not_generated.append(("firewall_exceptions.xlsx",
                              excel_message or "Excel output not requested"))
    if not_generated:
        print("Not generated this run:")
        for name, reason in not_generated:
            print(f"- {name}: {reason}")
    if removed:
        print("Stale artifacts from previous runs removed: " + ", ".join(removed))
    for problem in skipped:
        print(f"warning: {problem}")
    if diagram.message:
        print(diagram.message)
    if excel_message:
        print(excel_message)
    log.info("Analysis complete")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Run one analyzer invocation and release only its owned log handlers."""
    configure_bundled_graphviz()
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if effective_argv and effective_argv[0] in {"doctor", "preflight"}:
        from .preflight import main as preflight_main

        return preflight_main(effective_argv[1:], command=effective_argv[0])
    if effective_argv and effective_argv[0] == "update":
        from .update import main as update_main

        return update_main(effective_argv[1:])
    logger = logging.getLogger("nmap_flow_analyzer")
    try:
        return _main(effective_argv)
    finally:
        close_invocation_logging(logger)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
