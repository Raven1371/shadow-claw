# Migration notes

This file covers v1.1.1 -> v1.2.0 and v1.2.0 -> v1.2.1. The v1.2.1 section
is at the end.

## Migrating from v1.1.1 to v1.2.0

v1.2.0 adds optional Zeek passive-sensor correlation. **No action is
required for Nmap-only use**: every existing CLI option, package import,
output filename, configuration key, and Nmap-only output schema is
unchanged, and all new data-model fields are append-only.

## What is new

- `--zeek-dir PATH` (repeatable), `--zeek-format auto|json|tsv`,
  `--zeek-required`.
- An optional, strictly validated `zeek:` configuration section (see
  `network_config.example.yaml`); omitting it keeps prior behavior.
- Seven new output artifacts, generated **only** when `--zeek-dir` is
  supplied: `zeek_observed_flows.csv/.json`,
  `correlation_findings.csv/.json`, `external_dependencies.csv/.json`,
  `zeek_input_summary.json`. They participate in overwrite collision
  checks, atomic publication, the manifest, and stale cleanup — so a later
  Nmap-only `--overwrite` run cleanly removes stale Zeek artifacts from a
  previous combined run.

## Schema notes (append-only)

- `Flow`, `FirewallRule`, and `ServiceRecord` rows gain new columns
  (`evidence_sources`, `correlation_status`, `nmap_observation`,
  `zeek_observation`, first/last seen, connection and byte counters, Zeek
  conn states/services, sample UIDs, DNS/TLS/HTTP names,
  `sensor_quality`). Existing columns keep their names, order relative to
  each other, and meanings. CSV consumers that select columns by header
  name are unaffected; consumers that assume a fixed column count should
  switch to header-based access.
- `normalized_data.json` gains top-level `zeek_input_metadata`,
  `zeek_sensor_health`, `zeek_flow_aggregates`, `endpoint_identities`,
  `correlation_findings`, and `external_dependencies` keys on combined
  runs; existing keys are untouched.
- `run_manifest.json` gains a `zeek` provenance block on every run
  (`requested: false` for Nmap-only runs).
- The HTML report title becomes "Nmap + Zeek Flow Analysis Report" and the
  diagram title "Network Data-Flow Diagram (Nmap + Zeek)" only on combined
  runs.

## Semantics worth knowing

- Only successful Zeek connections can support candidate rules; failed,
  rejected, one-way, and partial traffic never does.
- The Nmap scanner's own traffic seen by Zeek is marked and excluded from
  production-dependency rules by default
  (`zeek.exclude_nmap_scanner_traffic_from_rules`).
- Nmap-exposed services without observed traffic are labeled "Not observed
  during the Zeek collection window", never "unused".
- External dependencies are report-only unless
  `zeek.include_external_dependencies_in_rules: true`, and even then use
  concrete IPs through full policy review.

# Migrating from v1.0 to v1.1

Existing commands keep working: no CLI flags, entry points, or output
filenames were removed or renamed, and no existing CSV column or JSON field
changed meaning or position. Everything new is additive. The items below are
the behavioral differences you may notice.

## 1. Config additions (all optional)

Your v1.0 `network_config.yaml` loads unchanged. New sections you can add
(see `network_config.example.yaml` for a fully commented version):

- `rule_generation:` — perspective toggles and
  `enforcement_model: endpoint_and_network | endpoint_only | network_only`.
- `inference_policy:` — per-category inference control and
  `minimum_confidence_for_candidate_rule` (default 70).
- `global_policy:` — lowest-precedence approved networks.
- Extended zone form:
  `ZoneName: {cidrs: [...], approved_source_networks: [...],
  approved_destination_networks: [...]}`. The legacy list form still works.
- `defined_flows` entries accept `destination_port` as a synonym for `port`
  and an optional `service:` label.
- Host entries' `approved_source_networks` / `approved_destination_networks`
  are now *enforced*, not just stored (see item 4).

## 2. Defined flows produce two rules by default

In v1.0 a `defined_flows` entry produced one rule. In v1.1 it produces a
source-side outbound candidate **and** a destination-side inbound candidate
(each marked with a `perspective` field). To approximate the old
inbound-only output:

```yaml
rule_generation:
  generate_source_outbound: false
  generate_destination_inbound: true
```

## 3. Inferred outbound is stricter

`--include-inferred-outbound` now follows `inference_policy`:

- Dependencies are only inferred toward explicitly configured
  `infrastructure:` entries; an *empty but declared* list produces a
  manual-review item instead of a broad rule.
- AD dependencies apply only to role-compatible (by default Windows) hosts.
- Logging infers only the preferred transport (tcp/6514 by default);
  udp/514 requires an explicit `fallback_transports` entry.
- The former mail-relay, proxy, and authentication-server templates are no
  longer inferred at all (those `infrastructure:` keys are still accepted).
- Anything below `minimum_confidence_for_candidate_rule` (default 70 —
  patch_management and backup fall under this) is reported as a flow and a
  "Rule withheld" review item, but not as a candidate rule. Lower the
  threshold consciously if you want the old, less conservative behavior.

Expect *fewer* inferred rules than v1.0 for the same config.

## 4. Approved-network enforcement

Host/zone/global `approved_*_networks` lists are evaluated for every rule
(host > zone > global; the lists belong to the enforcement target; `/32`
never widened). New rule fields record the outcome. In normal mode
violations are kept but flagged (`policy_violation`, `policy_notes`); under
`--strict` they are withheld to manual review — a strict run may therefore
produce fewer rules than v1.0 until policies are reconciled.

## 5. Output changes

- CSV/Excel: new columns are **appended** after all v1.0 columns; parsers
  indexing by header name are unaffected.
- `normalized_data.json`: new per-flow/rule fields plus a top-level
  `run_status` object.
- Reports carry a second standing disclaimer about rule perspectives.
- Spreadsheet cells whose text starts with `=`, `+`, `-`, or `@` now carry
  a leading `'` so they display as literal text. If a downstream pipeline
  consumed such values from the *CSV bytes*, strip the leading `'` or run
  with `--no-spreadsheet-sanitization` (not recommended).

## 6. Re-running into the same directory

Re-running into an output directory that already holds generated reports
now requires `--overwrite`. Unrelated files in the directory never block a
run and are never touched.

## 7. Version note

`__version__` is now `1.1.0`. Two v1.0 unit tests that asserted the old
single-perspective defined-flow behavior were updated to the corrected
behavior; the rest of the v1.0 suite passes unchanged.

---

# Migrating from v1.1.0 to v1.1.1

No CLI, filename, or schema changes. Differences you may notice:

1. **`run_manifest.json`** now appears in the output directory, listing
   every generated file with size and SHA-256.
2. **`--overwrite` cleans stale artifacts**: old generated SVG/PNG (when
   rendering fails) and the old generated workbook (when `--excel` is not
   requested) are removed so the directory matches the current run.
   Unrelated files are never touched.
3. **The HTML report references the diagram** via
   `<img src="data_flow_diagram.svg">` instead of inlining SVG markup, and
   only when the SVG was rendered by the current run.
4. **Quoted Booleans are strict**: `"false"` now correctly disables a
   feature; invalid strings like `"disabled"` are configuration errors
   (previously any nonempty string acted as true). Audit configs that
   relied on the old buggy coercion.
5. **Symlinked outputs are refused** (exit code 2) rather than written
   through; a symlinked `--output-dir` is also refused — pass the real
   path.
6. Outputs are generated in a hidden staging directory inside the output
   directory and published atomically; a failed run leaves the previous
   reports intact.

## Upgrading from v1.2.3 to v1.2.4

No action required. v1.2.4 is a parser-hardening and wording-polish release:
no schema, output-format, or firewall-rule change; sample rule counts are
identical to v1.2.3. Two behavior notes:

- **Diagnostic and execution-log wording is now grammatical.** If you grep
  `execution.log` or CLI output for the old mechanical forms ("host(s)",
  "dependenc(ies)", etc.), update those patterns; the counts and structure are
  unchanged.
- **A file whose first meaningful line is an unrecognized `#` directive is now
  flagged indeterminate, not parsed as TSV.** In `--zeek-format auto`, only an
  exact Zeek directive (#separator, #set_separator, #empty_field, #unset_field,
  #path, #open, #fields, #types, #close) establishes native TSV. Arbitrary
  comments like `#random` or look-alikes like `#separator_fake` now produce a
  bounded warning and are skipped, instead of being parsed as TSV and failing
  with "data before #fields header". Genuine Zeek TSV logs are unaffected.
  Force parsing with `--zeek-format tsv` if you have a non-standard header.

## Upgrading from v1.2.2 to v1.2.3

No action required. v1.2.3 is a maintenance release: no CLI, configuration, or
artifact change. You may notice:

- **JSON logs with leading blank lines or a BOM now parse.** Previously such a
  log was misdetected as TSV and yielded zero records; it now parses
  correctly. If you had worked around this by stripping leading blanks, that
  workaround is simply no longer needed.
- **raw_records_read now includes malformed records.** It previously counted
  only usable records; it now counts every data record seen, so
  `raw_records_read == usable_records + malformed_record_counts`. Expect
  raw_records_read to rise for any log that contained malformed lines. The
  manifest now also exposes `usable_records`.
- **Per-file sample metadata no longer carries global totals.** If you read
  `samples_retained` / `samples_truncated` off individual `files_processed`
  entries, move to the new `log_type_summaries` array, which reports the
  global cap once per log type with `sample_scope: global_across_log_type`.
  Per-file entries now carry only per-file statistics plus `data_records_seen`.
- **Report wording is grammatically polished.** If you scraped narrative text
  expecting the old "(s)"/"(ies)" forms, update those parsers; counts and
  structure are unchanged.

New append-only fields: `log_type_summaries` in Zeek metadata and the
manifest; `data_records_seen` on each `files_processed` entry;
`raw_records_read` and `usable_records` in the manifest.

## Upgrading from v1.2.1 to v1.2.2

No action required. v1.2.2 is a maintenance release: no CLI, configuration, or
artifact change. You may notice:

- **Protocol-log input statistics are now correct.** If your `--zeek-dir`
  contained application-protocol logs (ssh, rdp, smb_*, kerberos, ldap, smtp,
  postgresql, etc.), v1.2.1 listed each such file twice in `files_processed`
  and double-counted its records. v1.2.2 lists each physical file once with
  accurate counts. Flow enrichment is unchanged (it always deduplicated
  values); only the input provenance is corrected.
- **Large files.log / notice.log are now fully counted.** Previously, once the
  bounded sample list filled (200 for files, 100 for notice), parsing stopped
  and the file could be missing from `files_processed`. Now the whole file is
  counted and `samples_retained` / `samples_truncated` record the truncation.
  Expect higher `record_counts` for such logs; stored samples are unchanged.
- **Corroboration counts include three-source communications.** A declared
  dependency Nmap confirmed open and Zeek observed is now counted as supported
  by both Nmap and Zeek, based on its `evidence_sources`, while keeping its
  `user-defined-and-zeek` primary status. Reports present this as overlapping
  evidence dimensions. `normalized_data.json` gained
  `unique_communications_supported_by_nmap_and_zeek` and
  `corroboration_by_evidence_overlap`; the older
  `unique_corroborated_communications` (primary-status subset) is retained.
- **Combined reports carry a Zeek-aware disclaimer.** Nmap-only reports are
  unchanged.

New append-only fields (safe to ignore): `samples_retained` /
`samples_truncated` in Zeek input metadata and on capped `files_processed`
entries; two corroboration keys in `zeek_summary_counts`.

## Upgrading from v1.2.0 to v1.2.1

No action required. v1.2.1 is a maintenance release: the CLI, configuration
schema, artifact names, and Nmap-only behavior are unchanged, and no
configuration key was added, renamed, or removed.

What you will notice after upgrading:

- **Declared dependencies that contradict the scan now stop generating
  rules.** If you declared a flow in `defined_flows` (or relied on an
  inferred one), Zeek observed it, and Nmap reported that port `closed`,
  `filtered`, or `open|filtered`, v1.2.0 emitted candidate rules. v1.2.1
  marks the flow `conflicting-evidence`, withholds every derived rule
  perspective, and files a manual-review item. Expect your inbound and
  outbound candidate counts to *drop* by exactly those conflicts, and expect
  matching new entries in `manual_review.csv`. This is the intended
  correction, not a regression.
- **Confidence values on Zeek-derived flows are lower when the sensor was
  degraded.** The numbers themselves changed (they were previously fixed at
  85/30 regardless of sensor quality). Any downstream tooling that asserted
  on exact confidence values for degraded captures needs its expectations
  updated; `confidence_notes` explains each reduction.
- **Summary counts changed meaning, not correctness.** Reports now
  distinguish unique communications from firewall perspectives, so a
  dependency that generated two perspectives is reported as one
  communication. Totals in `zeek_summary_counts` (new in
  `normalized_data.json`) are the machine-readable form.
- **The eight optional Zeek logs are now parsed if present.** If your
  `--zeek-dir` already contained `x509.log`, `notice.log`, `weird.log`, and
  the `known_*` or `software`/`files` logs, they previously had no effect and
  now contribute certificate enrichment, endpoint software observations, and
  additional findings. Expect a higher correlation-finding count from the
  same input. Remove those files from the directory if you do not want them
  considered.
- **Malformed-record counts may rise for the same logs.** Records that were
  silently discarded as unusable are now counted as malformed with
  `file:line` context. The aggregation result is unchanged; only the
  reporting of input quality improved.

New append-only fields (safe to ignore): `confidence_notes` on flows and
rules; `any_zeek_traffic_observed`, `non_scanner_zeek_traffic_observed`, and
`scanner_only_zeek_traffic_observed` on service records; `raw_records_read`
and `usable_records` in Zeek input metadata; `certificate_details`,
`software`, `known_services`, and `seen_in_known_hosts` on endpoint
identities; `zeek_summary_counts` in `normalized_data.json`.

