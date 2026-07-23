# Changelog

## v1.2.5 - Windows logging-lifecycle portability hotfix

- Analyzer-created console and `execution.log` handlers are now explicitly
  flushed, detached, and closed at the end of every invocation.
- Repeated in-process runs no longer accumulate handlers or duplicate log
  lines, and completed output directories can be renamed or deleted
  immediately on Windows.
- Parent-application, pytest, GUI, and unrelated handlers remain untouched.
- Corrected the approved singular wording for `1 row` and `1 record`.
- Analyzer decisions, firewall candidates, schemas, security controls, and
  deterministic identifiers are unchanged.

## v1.2.4 - parser-hardening and wording polish

Small, narrowly scoped maintenance release. No architectural, correlation,
evidence, confidence, firewall-rule, reporting, or publication change; rule
counts and all safety behavior are identical to v1.2.3. Two corrections, each
covered by regression tests in `tests/test_zeek_v124_regressions.py`.

### Fixed

1. **Diagnostic and execution-log wording.** The HTML and Markdown reports
   were already grammatically polished in v1.2.3, but several `logging`
   messages still emitted mechanical forms such as "4 host(s)", "1 external
   dependenc(ies)", "10 candidate inbound rule(s)", and
   "12 manual-review item(s)". All such messages - across the Nmap parser,
   config loader, flow builder, firewall-rule generators, Zeek correlation
   reasons, role inference, and the CLI Zeek summary - now use the existing
   centralized `pluralize` helpers, so `execution.log` and CLI output read
   naturally for zero, one, and many. No second pluralization implementation
   was introduced. Machine-readable JSON keys, CSV columns, correlation-status
   values, and enum identifiers were not touched.

2. **Stricter native Zeek TSV auto-detection.** In `--zeek-format auto`, the
   first meaningful line was classified as native Zeek TSV whenever it began
   with `#`, so arbitrary input such as `#random comment` or a look-alike such
   as `#separator_fake` was accepted as TSV. Detection now recognizes TSV only
   when the first whitespace-delimited token is an exact Zeek directive from a
   single immutable constant (`ZEEK_TSV_DIRECTIVES`: #separator, #set_separator,
   #empty_field, #unset_field, #path, #open, #fields, #types, #close), via a
   centralized `detect_zeek_format()` helper. JSON is still recognized by a
   leading `{`; anything else - unknown `#` directive, ordinary text, blank,
   whitespace-only, or BOM-only - is indeterminate and produces a bounded
   warning with filename and physical line number, never the untrusted line,
   never a duplicate `files_processed` entry, and never a counted data record.
   Leading blank lines, whitespace, BOM, gzip, rotated files, and valid TSV and
   JSON logs all continue to detect exactly as before. Explicit
   `--zeek-format json` and `--zeek-format tsv` still bypass detection while
   applying their normal structural validation.

### Changed
- Version is 1.2.4 in the package, CLI, HTML report metadata, and manifest.
- New helper `detect_zeek_format()` and constant `ZEEK_TSV_DIRECTIVES` in
  `zeek_parser.py`.
- Test suite grew from 379 to 403 tests.

### Compatibility
- No schema, output-format, or firewall-rule change. Nmap-only behavior and
  all sample rule counts are identical to v1.2.3. The only behavioral change is
  that a file whose first meaningful line is an unrecognized `#` directive is
  now flagged indeterminate instead of being parsed as TSV - which previously
  produced confusing "data before #fields header" errors anyway.

## v1.2.3 - ingestion, accounting, and report-wording corrections

Final maintenance release of the 1.2 line, intended for operational use with
human firewall-policy validation. No architectural change, no CLI or
configuration-schema change, no output-format removal; all v1.2.2 artifacts,
security controls, staged publication, firewall-rule safeguards, and Nmap-only
behavior are preserved. Each correction is covered by a regression test in
`tests/test_zeek_v123_regressions.py`.

### Fixed

1. **Blank-line and BOM-safe Zeek format auto-detection.** In `--zeek-format
   auto`, detection examined the first physical line, so a JSON Lines log that
   began with blank lines (or a UTF-8 BOM) was misclassified as native Zeek
   TSV and produced zero usable records with a "data before #fields header"
   error. Detection now scans to the first *meaningful* line - skipping empty,
   whitespace-only, and BOM-only lines - while buffering the skipped lines so
   physical line numbers in later parse errors stay correct. JSON is detected
   on a leading `{`, TSV on a leading Zeek `#` directive, and anything else
   yields a bounded "indeterminate" warning instead of being silently treated
   as TSV. Detection stays streaming (no whole-file read) and identical for
   plain, gzip, and rotated files. The JSON parser also tolerates a leading
   BOM on the first record. Leading blank lines in a log no longer change any
   result.

2. **Correct raw/data-record accounting.** `raw_records_read` excluded
   structurally malformed records, so the implied invariant did not hold. The
   parsers now surface every non-blank data record (malformed included) to the
   consumer, which counts it in `raw_records_read` before structural
   validation and then classifies it as usable or malformed. The invariant
   `data_records_seen == usable_records + malformed_records` now holds for
   both JSON and TSV. Blank lines, whitespace-only lines, and TSV header
   directives are never counted as data records. Malformed JSON, wrong
   top-level JSON types, TSV rows with the wrong field count, and records
   failing required-field validation (bad IP, timestamp, protocol, or port)
   are all counted, each with filename, physical line number, and a bounded
   sanitized reason that never echoes the hostile record. A per-file
   `data_records_seen` field was added, and the manifest now exposes
   `raw_records_read` and `usable_records`.

3. **Per-file versus global sample-retention metadata.** The global sample cap
   for bounded logs (files.log cap 200, notice.log cap 100) spans all rotated
   files of a type, but v1.2.2 copied the same global `samples_retained` /
   `samples_truncated` totals onto every physical file entry, implying each
   file independently used the full cap. `files_processed` entries are now
   strictly per physical file (filename, log type, format, size, records,
   malformed, data_records_seen). A new `log_type_summaries` roll-up reports,
   once per log type, the file count, record and malformed totals, and - for
   capped types - the global retention totals with
   `sample_scope: global_across_log_type`. Every file is still parsed and
   counted in full, and malformed records after the cap are still detected.

4. **Professional singular/plural report wording.** Narrative report text used
   mechanical constructions such as "1 flow(s)", "1 external dependenc(ies)",
   and "1 were observed". A centralized `pluralize` module (`count_noun`,
   `plural`, `were`, `has`, `verb`) now produces grammatically correct wording
   for zero, one, and many across the HTML executive summaries and headings,
   the Markdown summary, correlation-finding text, sensor-health notes, and
   CLI log output. Both generated sample reports contain none of "(s)",
   "(ies)", "was/were", or the "dependenc(ies)"/"communication(s)"/"flow(s)"
   forms. Compact labels in table headings are unchanged.

### Changed
- Version is 1.2.3 in the package, CLI, HTML report metadata, and manifest.
- `ZeekInputMetadata` gained `log_type_summaries` (append-only); each
  `files_processed` entry gained `data_records_seen`; the manifest gained
  `log_type_summaries`, `raw_records_read`, and `usable_records`.
- New module `nmap_flow_analyzer/pluralize.py`.
- Test suite grew from 337 to 379 tests.

### Compatibility
- All additions are append-only. `raw_records_read` keeps its name but now
  accurately means data records seen (usable + malformed); no other field
  changed name or meaning. Nmap-only output and all firewall-rule counts are
  unchanged from v1.2.2.

## v1.2.2 - protocol-ingestion, sample-cap, corroboration, and disclaimer fixes

Maintenance release. No architectural change, no CLI or configuration-schema
change, no output-format removal; all v1.2.1 artifacts, security controls,
staged publication, firewall-rule safeguards, and Nmap-only behavior are
preserved. Each correction below is covered by a regression test in
`tests/test_zeek_v122_regressions.py`.

### Fixed

1. **Application-protocol logs were processed twice.** ssh, rdp, smb_cmd,
   smb_files, smb_mapping, dce_rpc, kerberos, ntlm, ldap, ldap_search, smtp,
   postgresql, ntp, quic, and tunnel were read through two separate paths - a
   confirmation loop inside `apply_enrichment()` (v1.2.0) and
   `process_protocol_logs()` (v1.2.1) - so one physical file appeared twice in
   `files_processed` and its records were counted twice in `record_counts`,
   `raw_records_read`, and `malformed_record_counts`. The two paths are now a
   single streaming pass inside `apply_enrichment()`: each record is parsed
   once and drives uid correlation, the lowercase service confirmation, the
   human-readable protocol confirmation, and file/malformed accounting.
   `process_protocol_logs()` was removed and `PROTOCOL_CONFIRMATION_LOGS` now
   maps each log type to a `(service, label)` pair. Multiple distinct physical
   files (rotated, gzipped) are still each processed exactly once.

2. **Sample caps aborted parsing of the rest of the file.** files.log (cap
   200) and notice.log (cap 100) exited their loop with `break` once the
   stored-sample list was full, which stopped the generator before its
   file-accounting completion ran: the file could be missing from
   `files_processed`, later records went uncounted, and malformed records
   after the cap were never detected. Both loops now `continue` past the cap -
   the whole file is streamed and validated, only sample STORAGE is bounded.
   Record and malformed counts are complete regardless of position, and new
   `samples_retained` / `samples_truncated` metadata (also on each
   `files_processed` entry) records the truncation, e.g. "205 records
   processed; 200 samples retained". The remaining optional-log loops were
   reviewed; none had an equivalent premature break.

3. **Corroboration counts excluded three-source communications.** The count
   of communications supported by both Nmap and Zeek matched only
   `correlation_status == "nmap-and-zeek"`, so a declared dependency that Nmap
   confirmed open and Zeek observed (evidence sources nmap + zeek +
   user_configuration, primary status user-defined-and-zeek) was reported as
   "0 corroborated" despite explicit evidence from both tools.
   `supported_by_nmap_and_zeek()` now decides corroboration from
   `evidence_sources`, and `evidence_overlap_breakdown()` reports the
   overlapping dimensions (Nmap-and-Zeek only, declared with Nmap
   corroboration, inferred with Nmap corroboration) as unique communications.
   Primary correlation status is never changed to make a count work, and
   inbound/outbound perspectives of one communication are never double
   counted. The HTML executive summary and corroboration section, Markdown
   summary, Excel summary, `normalized_data.json`, and CLI completion output
   all now present these as overlapping evidence dimensions, and the report
   wording makes the overlap explicit. The sample PostgreSQL communication is
   now counted as supported by both Nmap and Zeek, one unique communication
   with two firewall perspectives, keeping its user-defined-and-zeek status.

4. **The combined report used an Nmap-only disclaimer.** The header and footer
   described only Nmap scanner reachability even though the report also
   contains passive Zeek observations, sensor health, external dependencies,
   application identities, and correlation findings. A new
   `COMBINED_DISCLAIMER` is selected for the HTML report, Markdown summary, and
   `normalized_data.json` whenever a Zeek report is present; it states that
   Nmap describes reachability from the scanner's location while Zeek describes
   only traffic visible to its sensor, that neither independently proves a
   communication is authorized/required/complete/representative, and that
   candidate rules require policy and business-owner validation. Nmap-only
   reports keep the original wording verbatim. Both disclaimers remain
   HTML-escaped.

### Changed
- Version is 1.2.2 in the package, CLI, HTML report metadata, and manifest.
- `ZeekInputMetadata` gained `samples_retained` and `samples_truncated`
  (append-only); capped `files_processed` entries gained `samples_retained`
  and `samples_truncated`.
- `normalized_data.json` `zeek_summary_counts` gained
  `unique_communications_supported_by_nmap_and_zeek` and
  `corroboration_by_evidence_overlap`; the prior
  `unique_corroborated_communications` (primary-status subset) is retained.
- Test suite grew from 306 to 337 tests.

### Compatibility
- All additions are append-only. No existing field changed name or meaning,
  Nmap-only output is unchanged, and no firewall-rule count changed except as
  required by these corrections (the sample counts are unchanged from v1.2.1).

## v1.2.1 — correlation, provenance, and reporting corrections

Maintenance release. No architectural change, no CLI or configuration-schema
change, no output-format removal; all v1.2.0 artifacts, security controls,
staged publication, and Nmap-only behavior are preserved. Every correction
below is covered by a regression test in `tests/test_zeek_integration.py`.

### Fixed

1. **Declared and inferred flows no longer bypass conflicting Nmap states.**
   The existing-flow branch of the correlation path returned as soon as it
   recognized a configured or inferred flow, so a dependency declared in
   `defined_flows` that Zeek observed was labeled `user-defined-and-zeek`
   even when Nmap had reported the destination port `closed`, `filtered`, or
   `open|filtered` — and could produce inbound and outbound candidate rules
   on contradictory evidence. The Nmap destination-state check now runs for
   every Zeek-observed flow before that branch returns, whatever its prior
   evidence class (declared, expected-outbound, inferred, or Nmap-derived).
   A conflicting state sets `correlation_status: conflicting-evidence`,
   populates `nmap_observation` and a `manual_review_reason` that states what
   each source reported and that the observations differ in time and
   perspective, emits a correlation finding and a manual-review item, and
   withholds every rule perspective derived from the flow. The flow itself is
   retained in the report as observed traffic with conflicting scan evidence.

2. **The advertised optional Zeek logs are now actually parsed.**
   `x509`, `known_hosts`, `known_services`, `known_certs`, `software`,
   `files`, `notice`, and `weird` were discoverable — they appeared in
   `log_types_found` — but nothing consumed them, so they never reached
   `files_processed` and never affected analysis. All eight are now parsed by
   `process_optional_logs()`: `x509.log` records are indexed by file id and
   correlated with `ssl.log` `cert_chain_fuids` and
   `client_cert_chain_fuids`, with bounded certificate metadata (subject,
   issuer, serial, validity window, key algorithm and length, signature
   algorithm, identifier, chain position). Server chains attach to the
   **responder**, client chains to the originator; the two are never mixed.
   `known_hosts` is presence evidence only, `known_services` is supporting
   service evidence that cannot substitute for successful `conn.log`
   evidence in rule generation, `known_certs` is de-duplicated against x509
   enrichment by file id, `software` observations are bounded and never
   auto-classified as vulnerabilities, `files` records basename-only
   metadata with no contents or directory paths, `notice` entries become
   findings explicitly described as alerts for human assessment rather than
   confirmed vulnerabilities, and `weird` becomes a bounded protocol-anomaly
   summary rather than evidence of compromise. Every opened file now appears
   in `files_processed` with filename, log type, detected format, size,
   parsed record count, and malformed count.

3. **Sensor degradation now reduces numerical confidence.** `sensor_quality`
   was set to `degraded` while the confidence number was left untouched, and
   one path contained an effective no-op where the comment promised a
   reduction. Confidence is now produced by a single documented function,
   `compute_zeek_confidence()`, with deterministic penalties: base 85 for a
   successful Zeek flow (30 for attempted-only), −10 global degraded sensor,
   −10 aggregate missed bytes, −5 capture loss above the configured
   threshold, −15 partial observation, −20 ambiguous observation, −30
   unusable sensor, clamped to [20, 100]. It is applied identically to newly
   created and merged flows; a merged flow takes the lower of its prior and
   its Zeek confidence. Reduced confidence never deletes an observed flow,
   the reasons are recorded in the new `confidence_notes` field and in the
   evidence text, and flows from an unusable sensor are withheld from rule
   generation pending manual review.

4. **Scanner traffic no longer produces contradictory service reporting.** A
   service touched only by the Nmap scanner's own probes could be described
   as corroborated by Nmap and Zeek in one place and "not observed during the
   Zeek collection window" in another. `ServiceRecord` now tracks
   `any_zeek_traffic_observed`, `non_scanner_zeek_traffic_observed`, and
   `scanner_only_zeek_traffic_observed` separately. A scanner-only service is
   reported as observed only in scanner-generated traffic, with its own
   report section and finding, and is never filed under a plain "not
   observed" heading; the executive summary distinguishes all three states.
   Scanner traffic remains excluded from production rules by default.

5. **Merged evidence keeps its full provenance.** A flow could carry an Nmap
   observation while `evidence_sources` listed only `user_configuration` and
   `zeek`. Nmap corroboration of the destination service is now always added
   to the provenance, whatever the primary correlation status, and all
   provenance edits go through `order_evidence_sources()` / 
   `add_evidence_source()`, which de-duplicate and apply the canonical order
   nmap, zeek, user_configuration, inference. No prior evidence is dropped
   when records merge.

6. **Unique communications are separated from firewall perspectives.**
   Summaries counted the destination-inbound and source-outbound
   perspectives of a single dependency as two observed flows, inflating the
   reported totals. `communication_key()` / `count_communications()` define a
   communication as (originator, responder, transport, responder port), and
   the executive summary, section headings, Zeek-only / declared-and-observed
   / corroborated sections, Markdown summary, Excel sensor-health sheet, and
   the new `zeek_summary_counts` block in `normalized_data.json` now report
   unique communications and firewall perspectives as separate, explicitly
   labeled numbers.

7. **Structurally valid records missing core fields count as malformed.** A
   JSON or TSV `conn.log` record that parsed but lacked the fields needed to
   build a connection was counted as parsed and then dropped silently.
   `validate_conn_record()` now runs in the parser, while filename and line
   number are still known, requiring `ts`, `id.orig_h`, `id.resp_h`, `proto`,
   and a valid responder port for TCP and UDP — ICMP is exempt and keeps its
   own semantics rather than being forced into the port model. Invalid
   records increment `malformed_counts`, record `file:line` with a bounded
   sanitized reason that never echoes hostile record content, and are
   excluded from aggregation. Metadata now distinguishes
   `raw_records_read`, `usable_records`, and malformed counts per log type.

8. **The documented test command exists in the archive.** v1.2.0 cited
   `python3 run_tests.py`, which was not shipped. A real `run_tests.py` is
   now included and tested: it discovers `tests/test_*.py`, supports `-k`
   and `-v` and explicit paths, and needs only the standard library, so the
   suite runs on air-gapped or pip-restricted hosts. `python -m pytest -q`
   remains the standard command and is unchanged.

9. **Sample and summary counts are labeled accurately.** Completion output
   conflated total inbound candidates with those carrying top-level Observed
   evidence, reporting nine where ten rules were generated. The CLI now
   prints "Total inbound candidates: N (M with top-level Observed evidence)"
   and the equivalent outbound line, plus unique Zeek communications,
   perspectives, conflicting communications, and scanner-only services.

### Changed
- Version is 1.2.1 in the package, CLI, HTML report metadata, and run
  manifest.
- `tests/zeek-sample` (shipped fixture) gained `x509`, `known_hosts`,
  `known_services`, `known_certs`, `software`, `files`, `notice`, and
  `weird` logs so the sample exercises certificate enrichment and the
  supporting-log findings.
- Test suite grew from 253 to 303 tests.

### Compatibility
- `Flow`/`FirewallRule` gained `confidence_notes`; `ServiceRecord` gained the
  three traffic-observation booleans; `ZeekInputMetadata` gained
  `raw_records_read` and `usable_records`; `EndpointIdentity` gained
  `certificate_details`, `software`, `known_services`, and
  `seen_in_known_hosts`; `normalized_data.json` gained `zeek_summary_counts`.
  All additions are append-only — no existing field changed name or meaning,
  and Nmap-only output is byte-comparable in structure to v1.2.0.

## v1.2.0 — Zeek passive-sensor correlation release

### Added
- **Optional Zeek ingestion** via `--zeek-dir` (repeatable), `--zeek-format
  auto|json|tsv` (auto-detected per file; mixed directories supported), and
  `--zeek-required` (missing/unusable conn.log becomes fatal instead of a
  warning). Nmap-only behavior is unchanged when `--zeek-dir` is absent, and
  Zeek does not need to be installed to parse its logs.
- New modules: `zeek_models`, `zeek_parser` (streaming JSON Lines and native
  TSV, rotated and `.gz` logs, symlinks never followed, hard line/record
  safety limits), `zeek_aggregation` (centralized connection-outcome
  classification, per-originator/responder/protocol/port aggregation,
  uid-based enrichment, sensor-health assessment), and `zeek_correlation`
  (evidence merging across Nmap, Zeek, configuration, and inference).
- Connection outcomes: successful / failed / rejected / one-way / partial /
  ambiguous, with documented TCP conn_state semantics, responder-evidence
  requirements for UDP, and conservative ICMP handling (never port rules).
- Append-only fields on `Flow`, `FirewallRule`, and `ServiceRecord`:
  `evidence_sources`, `correlation_status`, `nmap_observation`,
  `zeek_observation`, first/last seen, connection/byte/packet counters,
  conn states, Zeek services, sample UIDs, DNS/TLS/HTTP names, and
  `sensor_quality`.
- Correlation statuses: nmap-reachability-only, zeek-traffic-only,
  nmap-and-zeek, user-defined-only, user-defined-and-zeek, inferred-only,
  attempted-only, conflicting-evidence, not-correlated.
- Unified endpoint inventory (`EndpointIdentity`) distinguishing Nmap
  scanned / Zeek observed / Nmap and Zeek / Configuration only / External,
  with identity precedence config > Nmap > DHCP > DNS alias > IP; HTTP
  hosts, TLS SNI, and certificate identities never replace device hostnames.
- Correlation findings and neutral discrepancy reporting (never labeled
  vulnerabilities), external-dependency reporting, Zeek sensor health
  (healthy / degraded / unknown / unusable; missing capture_loss.log means
  unknown, never healthy), and scanner-traffic marking/exclusion.
- New artifacts (combined runs only, fully integrated with collision
  checks, staged atomic publication, manifest, and stale cleanup):
  `zeek_observed_flows.csv/.json`, `correlation_findings.csv/.json`,
  `external_dependencies.csv/.json`, `zeek_input_summary.json`.
- `normalized_data.json`: append-only `zeek_input_metadata`,
  `zeek_sensor_health`, `zeek_flow_aggregates`, `endpoint_identities`,
  `correlation_findings`, `external_dependencies` sections (bounded
  aggregates and samples only, never raw log records).
- `run_manifest.json`: `zeek` provenance block (directories, files, formats,
  sizes, record and malformed counts, window, sensor health, warnings; no
  secrets, no full HTTP query strings).
- HTML report: dynamic "Nmap + Zeek Flow Analysis Report" title and new
  sections (data sources/windows, sensor health, unified endpoints,
  Zeek-observed communications, corroborated flows, declared-and-observed
  flows, unobserved exposures, Zeek-only services, attempted traffic,
  external dependencies, identity enrichment, correlation discrepancies);
  extended executive summary; Markdown summary counts; four new Excel
  sheets (Zeek Observed Flows, Correlation Findings, External Dependencies,
  Zeek Sensor Health).
- Diagram: unified "Network Data-Flow Diagram (Nmap + Zeek)" mode showing
  actual Zeek initiators and responders with distinct edge styles for
  scanner reachability, Zeek traffic, corroborated, declared-unobserved,
  inferred, attempted, and manual-review edges; bounded logarithmic edge
  thickness; distinct external-endpoint styling. Nmap-only diagrams keep
  the existing appearance and title.
- `zeek:` configuration section (strictly validated: CIDRs, IPs,
  percentages, positive limits, strict Booleans, unknown-key warnings).
- `docs/ZEEK_COLLECTION.md` collection guide and
  `scripts/zeek_process_pcap.py` (offline PCAP processing only; list-args
  subprocess, no shell, refuses unsafe overwrites, never captures live
  traffic).
- Deterministic combined Zeek sample fixture in `examples/zeek-sample/` and
  a combined sample output in `examples/sample-output-combined/`.

### Safety and semantics guarantees
- Failed, rejected, unanswered, one-way, and partial traffic never creates
  allow rules. Nmap scanner traffic is marked and excluded from
  production-dependency rules by default. Ignored sources/destinations stay
  in statistics but never generate rules.
- Nmap-only exposures are labeled "Not observed during the Zeek collection
  window" — never "unused", "unneeded", or "safe to remove".
- Scanner-sourced Nmap flows are never merged with production client flows;
  evidence for identical canonical communications is merged, never
  discarded.
- All Zeek-derived strings pass through the existing HTML, Markdown, DOT,
  Mermaid, and spreadsheet-formula sanitization. All prior protections
  (atomic staged publication, output validation, symlink protection, stale
  cleanup, Graphviz timeout, strict Booleans, no Any/Any, strict-mode
  withholding, policy evaluation, deterministic ordering, bounded-memory
  parsing) are unchanged.
- The analyzer remains read-only: no scans, no network connections, no
  firewall changes, no live capture. Test suite grew from 170 to 253 tests.
## v1.1.1 — Output-safety and configuration-correctness release

### Security

- **Stale/malicious SVG reuse — fixed.** The HTML report previously
  embedded whatever `data_flow_diagram.svg` existed on disk; after a
  Graphviz failure under `--overwrite` this could inline a stale — or
  attacker-planted, script-bearing — SVG. Diagram inclusion is now driven
  solely by the current run's `DiagramResult`, the image is referenced via
  `<img>` (SVG scripts do not execute when loaded as an image), symlinked
  SVGs are never referenced, and on failure the report prints
  "Diagram image rendering was unavailable for this run. DOT and Mermaid
  source files were generated."
- **Symbolic-link output redirection — fixed.** New
  `nmap_flow_analyzer/output_safety.py` validates every artifact before
  creation, replacement, or deletion: symlink destinations, symlinked
  parents, symlinked output directories, destinations resolving outside
  the output directory, and non-regular files (directories, FIFOs,
  sockets, devices) are all rejected; `O_NOFOLLOW` is used where
  available; nothing is ever recursively deleted except the run's own
  staging directory. A symlinked generated output aborts the run (exit 2)
  with the external target untouched.
- **Stale artifacts under `--overwrite` — fixed.** Outputs are generated
  in `out/.nmap-flow-analyzer-stage-<run-id>/`, validated, and atomically
  published; afterwards, generated files from previous runs that this run
  did not produce (old SVG/PNG after a rendering failure, the old
  workbook when `--excel` wasn't requested) are removed. Candidates come
  only from the previous `run_manifest.json` plus a hardcoded legacy
  allowlist; symlinks/special files are skipped with a warning; unrelated
  files are always preserved.
- **Incomplete atomic writes — fixed.** DOT, Mermaid, SVG, PNG, Excel,
  and the manifest are now written atomically (validated temp file,
  `fsync`, `os.replace`, cleanup on failure); Graphviz renders to a temp
  name and partial output is never published; the Excel workbook is saved
  to a temp file, verified by reopening with openpyxl, then swapped in —
  a failure never truncates the previous workbook. `execution.log`
  remains the one streamed, non-atomic output (documented).

### Correctness

- **Quoted Boolean YAML values — fixed.** `"false"`, `"no"`, `"off"`,
  `"0"` now parse as False everywhere (`rule_generation.*`,
  `inference_policy.*.enabled`, approved-service `approved`); invalid
  values ("", "disabled", 2, lists, null, ...) raise a clear ConfigError
  instead of silently coercing to True via `bool(value)`.
- **Run manifest and run context.** `run_manifest.json` records version,
  run ID, timestamps, input, per-file size and SHA-256, Graphviz and
  Excel results, and sanitization status; the completion summary lists
  "Generated this run" and "Not generated this run" with reasons; the
  HTML "Run status" section now includes version, run ID, overwrite mode,
  Graphviz availability/timeout, per-image render results, Excel
  requested/generated, artifact count, and warnings.
- **Documentation** corrected to describe actual atomic-write coverage
  and remaining limitations instead of a blanket claim.

### Compatibility

- No CLI, filename, or schema changes; all v1.1.0 tests pass (suite grew
  from 127 to 170). Version: 1.1.1.


## v1.1.0 — Security corrections and rule-modeling fixes

### Security

- **Spreadsheet formula injection (CSV + Excel) — fixed.** Untrusted scan
  values (hostnames, banners, NSE output, command line) written to
  `*.csv` and `firewall_exceptions.xlsx` could previously start with `=`,
  `+`, `-`, or `@` and be executed as formulas by spreadsheet software.
  All string cells are now sanitized centrally
  (`nmap_flow_analyzer/sanitization.py`); values are preserved as literal
  text with a leading `'`, numeric types and IPs/CIDRs/timestamps are
  untouched. Opt-out via `--no-spreadsheet-sanitization` (logged, and
  recorded in the Executive Summary and Run status).
- **Graphviz DOT / Mermaid label injection — fixed.** Labels now escape
  quotes, backslashes, braces, pipes, angle brackets, and line breaks
  (DOT) and are entity-encoded (Mermaid); crafted hostnames can no longer
  add nodes/edges or break diagram syntax. HTML escaping extended to all
  untrusted values; Markdown summaries escape pipes, backticks, and inline
  HTML.
- **Unbounded parser memory — fixed.** `iterparse` streaming already
  cleared processed `<host>` elements; the (empty) children accumulating
  under the root are now dropped as well, keeping memory bounded on very
  large reports. Verified with a 600-host fixture.
- **Silent report overwrite — fixed.** Without `--overwrite`, an output
  directory that already contains generated reports is refused with a
  clear message. Only the tool's own known filenames are ever considered
  or replaced; unrelated files never block a run and are never modified or
  deleted. All report writes are atomic (temp file + rename) with cleanup
  on failure.
- **Graphviz hangs/failures — fixed.** Rendering is bounded by
  `--graphviz-timeout` (default 60 s); missing binary, timeout, and
  nonzero exit are each handled and reported without failing the run, and
  the `.dot`/`.mmd` sources are always kept.

### Rule modeling

- **Defined flows now generate both rule perspectives.** A declared
  dependency (e.g. `web01 -> db01 tcp/5432`) produces a source-side
  outbound candidate *and* a destination-side inbound candidate,
  controlled by the new `rule_generation` config
  (`generate_source_outbound`, `generate_destination_inbound`,
  `enforcement_model: endpoint_and_network | endpoint_only |
  network_only`). `network_only` emits one normalized network rule
  (`perspective: network`) per flow. Rules carry `perspective` and
  `enforcement_model` fields; deduplication, deterministic IDs, and the
  no-Any/Any guarantee are preserved; unresolvable endpoints go to manual
  review.
- **Approved-network policies are now enforced.**
  `approved_source_networks` / `approved_destination_networks` at host,
  zone (extended zone form), and `global_policy` level are evaluated with
  host > zone > global precedence; policies belong to the enforcement
  target. Each rule reports `source_scope_status`,
  `destination_scope_status`, matched policies, `policy_violation`, and
  `policy_notes`. `/32` entries are matched exactly, never widened.
  Equal-specificity conflicts become "Ambiguous Policy" (manual review);
  violations are flagged, or withheld under `--strict`; missing policy is
  a warning, not a rejection.
- **Per-component evidence.** New `service_evidence`,
  `source_scope_evidence`, `destination_scope_evidence`,
  `purpose_evidence`, `role_evidence`, and combined `flow_evidence`
  (e.g. `Observed + User-Defined`) on flows and rules; the original
  `evidence_class` is unchanged. Any manual-review component, or an
  Unknown service with inferred scope, makes the combination
  "Manual Review Required".
- **Inference is policy-driven and conservative.** The old static
  template list is replaced by `inference_policy`: per-category enable
  switches, DNS transports, preferred logging transport (fallbacks only
  when explicitly configured — never udp/514 *and* tcp/6514 by default),
  AD dependencies only for role-compatible hosts (Linux excluded unless
  explicitly listed), no self-dependencies, manual review instead of
  broad rules when a configured infrastructure list is empty, and a
  `minimum_confidence_for_candidate_rule` threshold (default 70) below
  which dependencies are reported but withheld to manual review. The
  former low-confidence mail-relay / proxy / authentication-server
  templates are no longer inferred.
- **Outbound rule builder honors withhold reasons.** Flows flagged for
  manual review (including below-threshold inferences and strict-mode
  scanner-zone conflicts) can no longer become outbound rules.
- **Scanner-source hardening.** IPv6 scanner addresses fully supported;
  invalid `--scanner-ip` rejected; a `--scanner-zone` that conflicts with
  CIDR-based zone mapping produces a warning (and withholds observed
  rules under `--strict`).

### Reports

- New fields in CSV (appended columns), JSON, HTML, and Excel; a "Run
  status" section (sanitization, Graphviz result, scanner source,
  enforcement model, firewall mode, strict mode, inference) in the
  findings summary, normalized data, HTML report, and Excel Executive
  Summary; and a second standing disclaimer: *"A user-defined or inferred
  dependency may require both a source-side outbound rule and a
  destination-side inbound rule, depending on the enforcement
  architecture."*

### Compatibility

- All v1.0 CLI invocations, entry points, output filenames, and existing
  CSV/JSON fields are unchanged; new fields are appended. Two original
  tests asserting the old single-perspective defined-flow behavior were
  updated to the corrected behavior; everything else passes unmodified.
  See `MIGRATION.md`.
