# Shadow Core Integration Boundary

This document defines a future integration boundary. It does not implement
Shadow Core or the complete Shadow Evidence format.

> Shadow Core owns shared evidence, schema, validation, provenance,
> compatibility, and package-format behavior.
>
> Shadow Claw owns offline investigation, parsing, correlation, findings,
> diagrams, reports, and candidate recommendations.

## Ownership

Shadow Core owns shared evidence schemas, evidence-package structure, manifest
validation, deterministic serialization, compatibility negotiation, hashing,
provenance, lineage, normalized security-event definitions, import validation,
safe extraction, and package export rules.

Shadow Claw owns offline investigation; Nmap and Zeek parsing; future PCAP,
PCAPNG, and Suricata parsing; observation correlation; asset, service, and
communications analysis; findings; diagrams; reports; candidate firewall
recommendations; investigative timelines; and analyst-facing conclusions.

No Shadow Core implementation is copied into this repository. Shadow Claw will
consume a separately versioned Core boundary when that integration is approved.

## Ecosystem principles

> Shadow Fang monitors and detects.
>
> Shadow Claw investigates and validates.
>
> Shadow Core ensures both applications understand the same evidence.

> The software recommends.
>
> The human decides.
>
> The human implements.

## Planned Shadow Evidence boundary

Future integration will support `<case-id>.shadowevidence.zip`. Core-defined
packages must account for original evidence preservation, Nmap XML, Zeek logs,
future PCAP/PCAPNG, future Suricata EVE JSON, normalized events, assets,
services, communications, flows, findings, timelines, hashes, provenance,
source identity, analytical perspectives, and compatibility metadata.

Shadow Claw must not create a competing evidence schema. Import and export must
use Core-owned manifest validation, deterministic serialization, hashing, safe
extraction, compatibility negotiation, and package rules.

## Lineage and confidence

One PCAP interpreted by a native parser, Zeek, and Suricata represents:

- one independent source;
- three analytical perspectives.

Multiple interpretations or repeated records from the same underlying evidence
must not be counted as independent corroborating sources. Future confidence
logic and tests must distinguish independent sources, analytical perspectives,
direct observations, inferred observations, and repeated records from one
source. Test fixtures must cover shared hashes/source identity across parser
perspectives and must prove that confidence does not inflate through duplicate
interpretation.

## Safety and rollback

Integration must preserve deterministic output, provenance, path traversal and
symlink defenses, atomic publication, closed file handles, reusable output
directories, and human-reviewed candidate recommendations. Compatibility
negotiation must fail safely on unsupported package versions. Rollback consists
of disabling the integration adapter while retaining current standalone input,
configuration, report, and CLI behavior.
