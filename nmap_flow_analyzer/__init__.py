"""Nmap XML flow analyzer for defensive network documentation and firewall-policy planning.

This package parses Nmap XML output and produces service inventories,
candidate firewall exception lists, data-flow diagrams, and manual-review
reports.  Every generated flow and rule carries an explicit evidence
classification so that observed reachability is never conflated with
confirmed production traffic.
"""

__version__ = "1.3.0"
TOOL_NAME = "nmap-flow-analyzer"

DISCLAIMER = (
    "This report describes services and reachability observed from the Nmap "
    "scanner\u2019s location. It does not independently prove normal production "
    "communications between all listed systems."
)

# Source-aware disclaimer for combined Nmap + Zeek reports (v1.2.2). Selected
# in place of DISCLAIMER only when a Zeek report is present, so Nmap-only
# output keeps the Nmap-only wording verbatim.
COMBINED_DISCLAIMER = (
    "This report combines Nmap reachability observations with communications "
    "visible to the Zeek sensor during the stated collection window. Nmap "
    "describes reachability from the scanner\u2019s location, while Zeek "
    "describes only traffic visible to its sensor. Neither source "
    "independently proves that a communication is authorized, required, "
    "complete, or representative of all network activity. Candidate firewall "
    "rules require policy and business-owner validation before implementation."
)
