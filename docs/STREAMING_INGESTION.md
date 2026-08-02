# Streaming PCAP, PCAPNG, and Suricata ingestion

Shadow Claw 1.5 adds the narrow reusable `nmap_flow_analyzer.ingestion`
library boundary. It imports only Shadow Core contracts and Python standard
library modules; it does not import Claw CLI, reports, recommendations, or
presentation code. Fang consumes this module without copying parser code.

Suricata EVE is processed one UTF-8 JSON object per bounded line. Supported
types are alert, flow, netflow, DNS, HTTP, TLS, SSH, fileinfo, anomaly, and
stats. Unknown types are counted and retained as generic records. Malformed,
partial, oversized, deeply nested, oversized-string, and oversized-array input
is diagnosed. Stats provide observed sensor health; missing stats never imply a
healthy sensor. Rule files are not executed: only bounded sid, rev, msg,
classification, priority, metadata, and reference fields are retained.

Classic PCAP supports both byte orders and microsecond/nanosecond timestamps.
Ethernet, VLAN, ARP, IPv4, IPv6, ICMP/ICMPv6, TCP, UDP, and basic DNS port
metadata are decoded. Packet payloads are not copied into normalized records,
and TCP streams are not reassembled. The bounded flow table uses deterministic
oldest-entry eviction and marks evictions incomplete.

PCAPNG supports section headers, interfaces, enhanced packets, safe validated
skipping for unknown/custom blocks, multiple sections/byte orders, and
section-local `section:interface` identity. Interface statistics, name
resolution, and simple-packet blocks are preserved/skipped as bounded metadata
in this initial milestone; complete option decoding is not claimed.

All adapters retain raw SHA-256, byte/line/packet/block references, parser and
normalizer versions, checkpoints, diagnostics, and source/perspective lineage.
No extension-only detection, packet decryption, unrestricted payload extraction,
automatic rule deployment, or automatic security enforcement is performed.
Windows validation and packaging remain deferred.
