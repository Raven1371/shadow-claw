# Shadow Claw PCAP and Suricata phase report

Starting main: `60c81e9ed9d8a73f806bf9451d2c930a9101afc4`.
Branch: `develop/pcap-suricata-ingestion-v1.5`.

Version 1.5.0.dev0 integrates bounded streaming EVE, PCAP, and PCAPNG adapters
additively. Existing Nmap and Zeek behavior remains the default when no new
flags are supplied. New inputs generate `ingestion_summary.json`, participate
in raw Shadow Evidence preservation, and cannot bypass existing firewall
candidate safety gates.

Parser dependency decision: Python standard library only; no new native or
third-party parser dependency, runtime download, or binary was introduced.
See `STREAMING_INGESTION.md` for the support matrix and limitations.

Local baseline (Windows development host, Python 3.12.13, generated 10,000
records; not a Linux claim): EVE processed 908,890 bytes at about 1.47 MB/s and
16,178 records/s with 1,970,668 peak traced bytes. Classic PCAP processed
580,024 bytes at about 0.66 MB/s and 11,300 packets/s with 1,641,802 peak traced
bytes. These are observations, not pass thresholds. The deterministic PCAPNG
fixture is covered; a generated PCAPNG throughput baseline remains pending.
