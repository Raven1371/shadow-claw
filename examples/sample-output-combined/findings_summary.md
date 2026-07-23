# Nmap Flow Analysis - Findings Summary

Generated 2026-07-22 05:55:05 by nmap-flow-analyzer 1.2.4.

> This report combines Nmap reachability observations with communications visible to the Zeek sensor during the stated collection window. Nmap describes reachability from the scanner’s location, while Zeek describes only traffic visible to its sensor. Neither source independently proves that a communication is authorized, required, complete, or representative of all network activity. Candidate firewall rules require policy and business-owner validation before implementation.

## Scan metadata

- Command line: `nmap -sS -sU -sV -O --script vuln,smb-protocols -oX sample-scan.xml 192.168.10.0/24`
- Nmap version: 7.95
- Started: Mon Jul  1 10:00:00 2026; finished: Mon Jul  1 10:06:40 2026 (4 hosts up)
- Scan types: syn, udp

## Counts

- Hosts parsed: 4
- Open services: 11
- Flows modeled: 17 (Observed 17, Inferred 0, User-Defined 0)
- Candidate inbound rules: 10
- Candidate outbound rules: 2
- Manual-review items: 12
- NSE security-relevant findings: 2

## Zeek correlation summary

- Zeek observation window (UTC): 2026-07-20T08:00:10+00:00 to 2026-07-20T08:02:10+00:00
- Zeek endpoints observed: 8
- Zeek aggregated flows: 6 (4 with successful connections, 1 failed/rejected only)
- Communications supported by both Nmap and Zeek (evidence-source overlap, any primary status): 1 unique (2 firewall perspectives)
  - Nmap-and-Zeek only: 0
  - Declared and observed with Nmap corroboration: 1
  - Inferred and observed with Nmap corroboration: 0
- Zeek-only communications: 2 unique (4 firewall perspectives)
- Conflicting-evidence communications (rules withheld): 0 unique (0 perspectives)
- Nmap-exposed services with non-scanner production traffic: 1
- Nmap-exposed services seen only in scanner-generated traffic: 1 (not production usage, and not evidence of disuse)
- Nmap-exposed services with no Zeek traffic at all: 9 (not evidence they are unused)
- External dependencies: 1
- Correlation findings: 15
- Zeek sensor health: degraded (Capture loss 2.50% exceeds the configured threshold (1.0%))

## High- and critical-risk exposed services

- **Critical** - legacy01.example.local (192.168.10.40) tcp/445 SMB: SMB exposed; restrict to trusted zones; SMBv1 dialect enabled per NSE output; Possible end-of-life software: Microsoft OS past end of support (verify manually; version detection is not proof); NSE script 'smb-vuln-ms17-010' reports VULNERABLE state
- **High** - dc01.example.local (192.168.10.10) tcp/445 SMB: SMB exposed; restrict to trusted zones; SMBv1 dialect enabled per NSE output
- **High** - db01.example.local (192.168.10.30) tcp/5432 PostgreSQL: Database service exposed outside an approved application/management scope
- **High** - legacy01.example.local (192.168.10.40) tcp/23 Telnet: Telnet: cleartext remote administration; Possible end-of-life software: Microsoft OS past end of support (verify manually; version detection is not proof)
- **High** - legacy01.example.local (192.168.10.40) tcp/9100 Raw Print: Printer service exposed; restrict to print servers/users; Possible end-of-life software: Microsoft OS past end of support (verify manually; version detection is not proof)

## Manual review required

- **MR-0001** [NSE cross-reference] (192.168.10.40 /): NSE script 'smb-os-discovery' output references 192.168.10.10 - Script output alone is not credible proof of a production traffic flow
- **MR-0002** [Policy: always review] (192.168.10.40 tcp/23): Telnet on tcp/23 matches policy.always\_manual\_review - Organization policy requires human review of this port/service
- **MR-0003** [Rule withheld] (192.168.10.10 tcp/53): Candidate inbound rule for DNS withheld - Service not listed in the host's approved\_services
- **MR-0004** [Rule withheld] (192.168.10.20 tcp/22): Candidate inbound rule for SSH withheld - Service not listed in the host's approved\_services
- **MR-0005** [Rule withheld] (192.168.10.40 tcp/23): Candidate inbound rule for Telnet withheld - Matched policy.always\_manual\_review
- **MR-0006** [Rule withheld] (192.168.20.15 tcp/443): Candidate outbound rule for SSL to 203.0.113.50 withheld - External dependency; candidate rules disabled by zeek.include\_external\_dependencies\_in\_rules
- **MR-0007** [Rule withheld] (203.0.113.50 tcp/443): Candidate inbound rule for SSL withheld - External dependency; candidate rules disabled by zeek.include\_external\_dependencies\_in\_rules
- **MR-0008** [Unapproved service] (192.168.10.10 tcp/53): DNS on tcp/53 is not in the host's approved\_services list - An approval list exists for this host and this service is absent
- **MR-0009** [Unapproved service] (192.168.10.20 tcp/22): SSH on tcp/22 is not in the host's approved\_services list - An approval list exists for this host and this service is absent
- **MR-0010** [Uncertain port state] (192.168.10.10 udp/123): udp/123 reported open\|filtered - Nmap could not distinguish an open port from a filtered one (common for UDP); treating it as reachable would be unsafe
- **MR-0011** [Uncertain port state] (192.168.10.30 udp/161): udp/161 reported open\|filtered - Nmap could not distinguish an open port from a filtered one (common for UDP); treating it as reachable would be unsafe
- **MR-0012** [Zeek sensor health]: Capture loss reached 2.50%, above the configured 1.0% threshold - Passive observations may be incomplete; absence of a flow is weaker evidence than usual

## Run status

- Application version: nmap-flow-analyzer 1.2.4
- Run ID: ea421da03123
- Output mode: staged atomic publication
- Overwrite: disabled
- Spreadsheet sanitization: applied
- Graphviz available: yes
- Graphviz timeout: 60s
- Graphviz rendering: succeeded
- SVG generated this run: yes
- PNG generated this run: yes
- Excel requested: yes
- Excel generated this run: yes
- Scanner source: known (192.168.1.50)
- Enforcement model: endpoint\_and\_network
- Firewall mode: stateful
- Strict mode: off
- Inferred outbound: disabled
- Zeek input: 13 files, 6 aggregated flows
- Zeek sensor health: degraded
- Generated artifact count: 23
- Warnings: none

## Assumptions

- Nmap results record reachability from the scanner's location at scan time; they are not a passive record of production traffic.
- Only ports reported 'open' are treated as confirmed reachable; 'open\|filtered' ports are uncertain and always require manual review; 'filtered' and 'closed' ports never generate allow rules.
- The scan originated from 192.168.1.50 (sec-scan01) in zone 'Management', as declared by the operator (not derivable from the XML).
- Firewall mode is 'stateful': no separate rules are generated for normal response traffic.
- Inferred outbound dependencies are disabled; outbound rules come only from the configuration (or stateless return paths).
- Security zones were mapped from the configuration file (Management, Servers, Workstations); hosts outside declared ranges are 'Internal' (local ranges) or 'Unknown'.
