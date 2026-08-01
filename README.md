# nmap-flow-analyzer

## License and Commercial Use

Project-owned code is source-available for free noncommercial use under the
PolyForm Noncommercial License 1.0.0. Permitted noncommercial use is governed
by the exact terms in [LICENSE](LICENSE), including the standard provisions for
noncommercial organizations and institutions. This is not an OSI-approved
open-source license.

Commercial use requires separate written authorization from Kache Flanery,
who retains project copyright. See [COMMERCIAL_USE.md](COMMERCIAL_USE.md).
Third-party components remain under their own licenses and notices. Shadow
Claw™, Shadow Fang™, Shadow Core™, Shadow Evidence™, and associated branding
are reserved as described in [TRADEMARKS.md](TRADEMARKS.md).

Parses an Nmap XML report and produces a network data-flow diagram, conservative inbound and outbound firewall exception lists, a service inventory, and a manual-review report — with every finding labeled by how it was established (Observed, Inferred, User-Defined, Unknown, or Manual Review Required).

> This report describes services and reachability observed from the Nmap scanner's location. It does not independently prove normal production communications between all listed systems.

That sentence appears in every generated report because it is the single most important caveat of this tool.

## 1. Installation

Requires Python 3.9+.

For a normal isolated Python tool installation:

```bash
pipx install .
nmap-flow-analyzer --help
```

For development:

```bash
cd nmap-flow-analyzer
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

`pyproject.toml` is the authoritative source for package metadata and
dependencies. `requirements.txt` is retained as a compatible runtime-only
mirror for legacy and closed-network installation workflows.

Inspect an installation without performing network access:

```bash
nmap-flow-analyzer doctor
nmap-flow-analyzer preflight --json --non-interactive
```

See `docs/PREFLIGHT.md` for checks, automation behavior, and Graphviz
resolution details. No automatic update checks are performed.

Optional, for SVG/PNG diagram rendering (the `.dot` and `.mmd` sources are always written even without it):

```bash
sudo apt install graphviz      # Debian/Ubuntu
sudo dnf install graphviz      # RHEL/Fedora
brew install graphviz          # macOS
winget install Graphviz.Graphviz   # Windows
```

## 2. Basic usage

```bash
python nmap_flow_analyzer.py --input full-scan.xml
```

Recommended conservative run:

```bash
python nmap_flow_analyzer.py \
  --input full-scan.xml \
  --config network_config.yaml \
  --output-dir out \
  --scanner-ip SCANNER_IP \
  --scanner-zone SCANNER_ZONE \
  --diagram-detail full \
  --firewall-mode stateful \
  --strict \
  --excel \
  --verbose
```

Optionally, once your `infrastructure:` and `inference_policy:` sections are
configured and you accept clearly labeled assumptions, add
`--include-inferred-outbound`.

Windows (PowerShell): same flags, use `python` and backtick or single-line form.

Flags:

| Flag | Meaning |
|---|---|
| `--input` | Nmap XML report (required) |
| `--config` | YAML environment configuration |
| `--output-dir` | Output directory (default `output/`) |
| `--scanner-ip` / `--scanner-zone` | Where the scan originated (overrides config) |
| `--diagram-detail summary\|full` | Service-level vs protocol/port-level edge labels |
| `--include-open-filtered` | Include `open\|filtered` ports as *Manual Review Required* flows (never as rules) |
| `--include-inferred-outbound` | Infer outbound dependencies (DNS/NTP/AD/...) from configured infrastructure — labeled *Inferred* |
| `--firewall-mode stateful\|stateless` | Stateless adds clearly-labeled return-path rules |
| `--excel` | Also write `firewall_exceptions.xlsx` (requires openpyxl) |
| `--strict` | Broad, ambiguous, or policy-violating rules are withheld and moved to manual review |
| `--overwrite` | Allow replacing previously generated reports in the output directory |
| `--graphviz-timeout N` | Max seconds for Graphviz rendering (default 60) |
| `--no-spreadsheet-sanitization` | Disable CSV/Excel formula-injection protection (NOT recommended) |
| `--verbose` | Debug logging to console and `execution.log` |

Try it immediately with the bundled sample:

```bash
python nmap_flow_analyzer.py --input examples/sample-scan.xml \
  --config network_config.example.yaml --output-dir /tmp/demo \
  --include-inferred-outbound --excel
```

## 3. Outputs

| File | Contents |
|---|---|
| `analysis_report.html` | Self-contained report (search/sort, print-ready, no CDN) |
| `service_inventory.csv/.json` | Every scanned port with state, evidence, risk |
| `inbound_exceptions.csv/.json` | Candidate inbound allow rules |
| `outbound_exceptions.csv/.json` | Candidate outbound allow rules |
| `manual_review.csv` | Everything a human must decide |
| `findings_summary.md` | Executive markdown summary |
| `data_flow_diagram.svg/.png/.dot/.mmd` | Diagram + editable sources |
| `firewall_exceptions.xlsx` | Optional multi-sheet workbook |
| `normalized_data.json` | Full machine-readable dataset |
| `execution.log` | Run log |

## 4. Configuration (`network_config.yaml`)

See `network_config.example.yaml` — it is fully commented. Sections:

- `scanner`: ip / hostname / zone. Declare this honestly; observed reachability is only proven from this point.
- `firewall_mode`: `stateful` (no return rules) or `stateless` (labeled return rules).
- `local_networks`, `zones`: prefix lists; most-specific prefix wins for zone assignment.
- `hosts.<ip>`: hostname, role (overrides inference at confidence 100), device_class, owner, purpose, `approved_services`, `expected_inbound` (with `sources`), `expected_outbound`, approved networks. Open services not in `approved_services` are flagged as unapproved.
- `infrastructure`: dns_servers, ntp_servers, domain_controllers, authentication_servers, logging_servers, patch_servers, backup_servers, mail_relay_servers, proxy_servers. Used only with `--include-inferred-outbound`.
- `defined_flows`: known application flows the scan cannot see — labeled User-Defined.
- `policy`: `default_source_scope` (scanner-ip | scanner-zone), `management_source`, `max_source_prefixlen_ipv4/6`, `always_manual_review`, `risk_overrides`.

## 5. Evidence classes — observed vs. inferred

- **Observed** — the scanner completed a probe (e.g. SYN-ACK on an open TCP port). Proves only *scanner → target* reachability at scan time.
- **Inferred** — likely dependency based on role and configured infrastructure (opt-in). Reasonable, but not proven.
- **User-Defined** — declared in YAML. Trusted as documentation, marked as unverified by the scan.
- **Unknown** — port state didn't confirm a service (filtered/closed).
- **Manual Review Required** — ambiguous (`open|filtered`), unapproved, mismatched, policy-flagged, or scope-problematic; a human must decide.

The tool never upgrades one class to another, never emits Any/Any rules, never widens sources beyond your policy without flagging it, and never creates outbound rules just because an inbound service is open.

A crucial limitation: **an Nmap scan sees listeners, not traffic.** It cannot tell you which clients actually use a service, in what volume, or when. Before treating these exceptions as "the" communication matrix, corroborate with real traffic evidence: packet captures (tcpdump/Wireshark), NetFlow/IPFIX/sFlow from switches or firewalls, Zeek connection logs, firewall hit counts, or SIEM data. Anything only this tool inferred should be confirmed there first.

## 6. Validating exceptions before production

1. Start from `manual_review.csv` — resolve every item.
2. Confirm each Observed rule against the actual client population (flow logs / captures), not just the scanner.
3. Verify Inferred and User-Defined rules with system owners.
4. Check `scope_warning` columns; tighten any widened sources.
5. Stage rules in log-only / audit mode on the firewall first; watch hit counts before enforcing.
6. Re-scan after implementation to confirm no unintended exposure remains.

## 7. Security notes & limitations

- XML is parsed with `defusedxml` when available (entity-expansion hardening).
- Version-based vulnerability findings are always "possible — verify manually"; only NSE `State: VULNERABLE` output is reported as Confirmed, and even then re-verification is recommended.
- IPv6, UDP, and `open|filtered` uncertainty are handled explicitly.
- The tool does not touch the network; it only reads the XML you provide.

## 8. Tests

The suite is plain pytest. Either command runs it:

```bash
python -m pytest -q                     # standard, requires pytest
python run_tests.py                     # shipped runner, no dependencies
```

`run_tests.py` is included in the archive and needs nothing beyond the
standard library, for air-gapped or pip-restricted hosts. Focused runs:

```bash
python -m pytest -q tests/test_zeek_parser.py
python -m pytest -q tests/test_zeek_aggregation.py
python -m pytest -q tests/test_zeek_correlation.py
python -m pytest -q tests/test_zeek_integration.py

python run_tests.py tests/test_zeek_integration.py
python run_tests.py -k certificate      # substring filter
```

Current suite: **303 tests**. See `TEST_RESULTS.txt` for the recorded run.

## 9. Troubleshooting

- *"Graphviz 'dot' not found"* — install graphviz (see above) or use the `.dot`/`.mmd` files with any renderer.
- *Excel export skipped* — `pip install openpyxl`.
- *Empty outputs* — check `execution.log`; commonly the XML has no host records (scan aborted or wrong file).
- *Config errors* — the loader reports every invalid field with its YAML path.

## 10. Security corrections (v1.1)

**Spreadsheet formula-injection protection (on by default).** Every string
written to CSV and Excel is neutralized when it could be interpreted as a
formula (`=`, `+`, `-`, `@`, including after leading whitespace or control
characters): a leading `'` makes spreadsheet software display it as literal
text. Non-string values (counts, genuine negatives) are untouched, as are
IPs, CIDRs, port ranges, and timestamps. `--no-spreadsheet-sanitization`
disables this for pipelines that post-process raw values — **not
recommended**; the Executive Summary and Run status record whether
sanitization was applied.

**Output-format escaping.** Hostnames, service banners, NSE output, owners,
and purposes are untrusted. HTML output escapes markup; Graphviz DOT labels
escape quotes, backslashes, braces, pipes, angle brackets, and line breaks;
Mermaid labels are entity-encoded; Markdown escapes pipes, backticks, and
inline HTML. Content is encoded, never removed.

**Bounded XML parsing.** Reports are parsed incrementally (`iterparse`,
`defusedxml` when installed: no DTDs, no external entities), with processed
elements freed, so very large reports parse in bounded memory.

**Output-directory safety.** A directory already containing generated
reports is refused unless `--overwrite` is given; only files this tool
generates (per the previous run's manifest plus a built-in allowlist) are
ever replaced or cleaned up, unrelated files are never touched or deleted,
and every artifact except the streamed `execution.log` is written
atomically (validated temp file + `fsync` + rename) with cleanup on
failure. Symbolic-link destinations and symlinked parent directories are
rejected before any write. See section 17 for v1.1.1 specifics.

**Graphviz safeguards.** Rendering is bounded by `--graphviz-timeout`
(default 60 s); missing binaries, timeouts, and nonzero exits are reported
without failing the run, and the `.dot`/`.mmd` sources are always kept.

## 11. Rule perspectives and enforcement models

A user-defined or inferred dependency may require **both** a source-side
outbound rule and a destination-side inbound rule, depending on the
enforcement architecture. For `web01 -> db01 tcp/5432`:

- outbound candidate on/for web01 (`perspective: source-outbound`)
- inbound candidate on/for db01 (`perspective: destination-inbound`)

`rule_generation` controls this:

```yaml
rule_generation:
  generate_source_outbound: true
  generate_destination_inbound: true
  enforcement_model: endpoint_and_network   # | endpoint_only | network_only
```

- `endpoint_and_network` (default): both endpoint perspectives are emitted;
  the flow entry in `normalized_data.json` is the normalized network-flow
  record for central firewalls.
- `endpoint_only`: identical rule output; no network-record semantics implied.
- `network_only`: **one** rule per declared flow (`perspective: network`)
  representing a single centrally enforced network rule — no duplicate
  endpoint rows. There is no separate output file; the network rule appears
  in the normal inbound list, marked by its perspective and evidence text.

Rule IDs remain deterministic, dedupe-safe, and never widen to Any/Any;
unresolvable endpoints go to manual review.

## 12. Evidence fields

Each flow and rule now carries component evidence in addition to the
original `evidence_class` (which is preserved unchanged for compatibility):

| Field | Meaning |
|---|---|
| `service_evidence` | How the service's existence was established |
| `source_scope_evidence` | Where the source scope came from |
| `destination_scope_evidence` | Where the destination scope came from |
| `purpose_evidence` | Where the business purpose came from |
| `role_evidence` | Whether the host role was configured or inferred |
| `flow_evidence` | Transparent combination, e.g. `Observed + User-Defined` |

Any component requiring manual review makes `flow_evidence`
"Manual Review Required", as does an Unknown service combined with any
inferred scope.

## 13. Approved-network enforcement

`approved_source_networks` / `approved_destination_networks` are enforced at
three levels — host, zone (extended zone form), and `global_policy` — with
the most specific applicable policy winning (host > zone > global). The
lists belong to the enforcement target: *its* approved sources are who may
reach it; *its* approved destinations are where it may send. A `/32` is
matched exactly and never widened; the rule's scope is never rewritten, only
classified. Every rule reports `source_scope_status`,
`destination_scope_status`, `matched_source_policy`,
`matched_destination_policy`, `policy_violation`, and `policy_notes`.
Statuses: Approved, Outside Approved Scope, No Policy Defined, Ambiguous
Policy (equal-specificity conflict → manual review). Violations are flagged
in normal mode and withheld to manual review under `--strict`. Absence of a
policy is a warning, never a rejection.

## 14. Inference policy

Inferred outbound dependencies remain **opt-in**
(`--include-inferred-outbound`) and are now governed by `inference_policy`
(see the example config): per-category enablement (dns, ntp, logging,
active_directory, patch_management, backup), DNS transports, the preferred
logging transport (fallbacks only when explicitly listed — never both
udp/514 and tcp/6514 by default), and AD dependencies only for
role-compatible hosts (Linux excluded unless its role is explicitly listed).
Self-dependencies are never inferred; empty configured infrastructure lists
produce manual-review items instead of broad rules; every inferred flow
names the policy entry, infrastructure entry, and confidence that produced
it; and dependencies below `minimum_confidence_for_candidate_rule`
(default 70) are withheld to manual review.

## 15. Validating candidate rules

Inbound: clear `manual_review.csv`; confirm each Observed rule's real client
population from NetFlow/IPFIX, Zeek, packet captures, or firewall hit
counts (the scanner is one client, not the population); resolve every
`policy_violation` and `scope_warning`. Outbound: confirm User-Defined and
Inferred dependencies with system owners and flow logs — an open inbound
service never implies outbound rules, and stateful mode never emits return
rules. Stage everything in log-only mode before enforcing, then re-scan.

A single Nmap report cannot prove normal traffic flows: it observes
listeners from one vantage point at one moment. It does not see clients,
volumes, schedules, or east-west traffic between scanned hosts.

## 16. Migration from v1.0

See `MIGRATION.md`. Summary: all v1.0 commands, file names, and fields are
preserved; new CSV/Excel columns and JSON fields are appended. Behavioral
changes: defined flows now produce both rule perspectives by default (set
`rule_generation` to restore single-sided output); inferred outbound is
policy-driven and more conservative; spreadsheet cells with formula-like
values gain a leading `'`; re-running into a used output directory now
requires `--overwrite`.

## 17. v1.1.1 output-safety release

**Current-run artifact tracking.** Reports never infer artifact existence
from the filesystem. A `RunContext`/`DiagramResult` records exactly what
this execution produced; the HTML report includes the diagram image only
when the SVG was rendered *by this run* (referenced as
`<img src="data_flow_diagram.svg">`, so scripts inside an SVG cannot
execute in the report document; a preexisting or symlinked SVG is never
embedded or referenced). When rendering fails the report states:
*"Diagram image rendering was unavailable for this run. DOT and Mermaid
source files were generated."*

**Staging and atomic publication.** All artifacts are generated inside
`out/.nmap-flow-analyzer-stage-<run-id>/`, validated, then atomically
moved (`os.replace`) into place; every destination is validated *before*
the first replacement, so a symlink or special file aborts the run with
exit code 2 and the previous reports remain untouched. A failure during
generation cleans the staging directory and leaves the prior run intact
(exit code 1). Remaining limitation: the final per-file renames are
individually atomic but not one multi-file transaction — after all
destinations pass validation, an OS-level failure mid-publication could in
principle leave a mix of old and new files; `run_manifest.json` and file
timestamps identify the affected run in that unlikely case. `execution.log` streams during the run and is
the one non-staged, non-atomic output.

**Run manifest.** `run_manifest.json` records the tool version, run ID,
timestamps, input, every generated file with size and SHA-256, Graphviz
availability/results, and Excel/sanitization status.

**Stale-output cleanup (`--overwrite`).** After successful publication,
generated files from previous runs that this run did not produce — old
SVG/PNG when rendering failed, the old workbook when `--excel` was not
requested — are removed so the directory reflects exactly the current run.
Candidates come only from the previous manifest and the built-in
allowlist; symlinks and special files are never followed or deleted (they
are skipped with a warning), and unrelated files are always preserved.

**Symlink protections.** Writing through a symlinked destination, a
symlinked parent, or a symlinked output directory is refused; destinations
resolving outside the output directory and non-regular files (directories,
FIFOs, sockets, devices) are rejected; `O_NOFOLLOW` is used additionally
where the platform provides it. On platforms without symlink support these
protections are inert and the tool functions normally.

**Strict Boolean configuration.** Every configuration Boolean
(`rule_generation.*`, `inference_policy.*.enabled`, approved-service
`approved`, ...) accepts only true/false, yes/no, on/off, 1/0 (any case)
or real Booleans/0/1 integers. A quoted `"false"` is False; anything else
(empty strings, `disabled`, `2`, lists, null) is a clear configuration
error instead of silently becoming True.

**Failure classes.** Fatal: parse/config errors, output-safety violations,
core report failures (nothing is partially replaced). Non-fatal: Graphviz
rendering and Excel export may fail with a logged reason — the run
completes, but their stale predecessors are removed and the manifest, run
status, and completion summary say exactly what was and wasn't generated.

## 18. Zeek passive-sensor correlation (v1.2.0)

The analyzer can optionally correlate the Nmap scan with logs from a Zeek
passive sensor. Nmap describes *reachability from the scanner*; Zeek
describes *traffic actually observed*; the YAML configuration describes
*declared intent*. v1.2.0 correlates all three without conflating them —
and remains a read-only tool: it never captures traffic, never connects to
the network, and never requires Zeek to be installed just to parse logs.

```sh
nmap-flow-analyzer --input scan.xml --config network_config.yaml \
    --zeek-dir ./zeek-logs --output-dir ./analysis --excel
```

- `--zeek-dir PATH` — may be repeated; directories of Zeek logs (JSON Lines
  or native TSV, rotated names and `.gz` supported, formats may be mixed;
  symbolic links are never followed).
- `--zeek-format auto|json|tsv` — default `auto` (detected per file).
- `--zeek-required` — make missing/unusable `conn.log` fatal; without it
  the run continues Nmap-only with a warning.

`conn.log` is the required core log. Every other supported log is optional
enrichment, and each one is genuinely parsed — a log is never discovered and
then ignored:

- `dns.log`, `dhcp.log`, `ssl.log`, `http.log` — endpoint identity (DHCP
  hostname > DNS alias; TLS SNI is never treated as a device identity).
- `x509.log`, `known_certs.log` — certificate metadata, correlated to
  `ssl.log` `cert_chain_fuids` / `client_cert_chain_fuids`. Server chains
  attach to the responder, client chains to the originator.
- `known_hosts.log` — presence evidence only, never proof of an open service.
- `known_services.log` — supporting service evidence; it cannot substitute
  for successful `conn.log` evidence when generating rules.
- `software.log` — bounded software observations, never auto-classified as
  vulnerabilities.
- `files.log` — basename-only transfer metadata; no contents, no directory
  paths.
- `notice.log` — findings described as alerts for human assessment, not
  confirmed vulnerabilities.
- `weird.log` — bounded protocol-anomaly summary, not proof of compromise.
- `ssh`, `rdp`, `smb_*`, `dce_rpc`, `kerberos`, `ntlm`, `ldap*`, `ntp`,
  `smtp`, `postgresql`, `quic`, `tunnel` — uid-matched application-protocol
  confirmations on flows `conn.log` already established.
- `capture_loss.log`, `reporter.log` — sensor health, which reduces the
  confidence of every observation the sensor produced.

See `docs/ZEEK_COLLECTION.md` for collection guidance, sensor-placement
limitations, and authorization requirements.

Combined runs additionally produce `zeek_observed_flows.csv/.json`,
`correlation_findings.csv/.json`, `external_dependencies.csv/.json`, and
`zeek_input_summary.json`, extend `normalized_data.json` and
`run_manifest.json` with append-only sections, add Zeek sections and an
extended executive summary to the HTML report and Excel workbook, and
switch the diagram to a unified "Network Data-Flow Diagram (Nmap + Zeek)"
showing real initiators and responders.

Key semantics:

- One aggregate per originator/responder/protocol/port — different clients
  of the same server are never merged, and the Nmap scanner's own traffic
  is marked and excluded from production-dependency rules by default.
- Only successful connections can support candidate rules; failed,
  rejected, unanswered, one-way, and partial traffic never does and is
  reported under "Attempted, rejected, and one-way communications".
- Candidate rules from Zeek use the actual observed originator and pass
  through the same policy, strict-mode, management-source, and no-Any/Any
  checks as every other rule. Observed traffic does not independently
  establish business authorization.
- Nmap-exposed services with no observed traffic are labeled "Not observed
  during the Zeek collection window" — never "unused" or "safe to remove".
- Sensor health (capture loss, missed bytes, reporter errors) is assessed
  and reported; a missing `capture_loss.log` means health is *unknown*,
  never assumed healthy. Degradation lowers confidence but never deletes
  observed flows. Zeek can only describe traffic visible to its sensor.
