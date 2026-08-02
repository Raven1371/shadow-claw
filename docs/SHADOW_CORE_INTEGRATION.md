# Shadow Core Integration

Shadow Claw `1.4.0.dev0` declares `shadow-core >= 0.1.0.dev0, < 0.2` and uses
Core for package construction, deterministic serialization, hashing, schema and
compatibility checks, hostile ZIP validation, and staged extraction. Core is
built as a wheel from its separate repository and is not vendored.

`--export-shadow-evidence` is additive. Existing reports, diagrams, rules,
formats, safety decisions, and the `nmap-flow-analyzer` compatibility command
remain in place. Original Nmap XML and supplied regular Zeek log files are
stored byte-for-byte with SHA-256 provenance. Normalized events, assets,
services, flows, communications, findings/timeline content, compatibility
metadata, source identity, and analytical perspectives are exported through
the Core contract.

Import and verification do not execute evidence. Core rejects unsafe members,
bad hashes, incompatible versions, malformed structured content, and resource
abuse before extraction. Import refuses an existing destination.

The current adapter cannot infer that independently supplied Zeek logs were
derived from a particular PCAP unless upstream evidence supplies that parent
identity. It therefore preserves known raw-file identity and never claims
cross-tool independent corroboration without explicit lineage metadata.

The separate Shadow Core GitHub remote does not yet exist. Local installation
uses the workspace build script. Linux CI consumption must be finalized after
the owner creates the authoritative Core remote or approves another immutable
artifact source.
