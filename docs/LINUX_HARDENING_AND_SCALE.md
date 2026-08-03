# Linux deployment hardening and scale validation

Shadow Claw 1.6 remains an offline-capable workstation/server analyzer. Build the wheel, source distribution, portable archive, one-file executable, DEB, RPM, and AppImage in disposable Ubuntu 24.04 and Rocky Linux 9 environments. Clean-host smoke tests must install only locally built artifacts and an offline wheelhouse, then exercise Nmap, Zeek, PCAP, PCAPNG, Suricata EVE, Shadow Evidence export/validation, output lifecycle, installation, and removal.

`scripts/benchmark-ingestion.py` deterministically generates mixed EVE, classic PCAP, and PCAPNG inputs using reserved addresses. The record bound is 1 to 1,000,000. It records OS, Python and parser versions, seed, bytes, records, wall time, CPU time, throughput, and peak traced memory. PR CI uses a small tier; manual Linux runs establish larger observations. Results are baselines, not arbitrary pass thresholds. Generated files are temporary and must not be committed.

Upgrade from 1.5 by validating the existing configuration and Shadow Evidence 0.1.0 packages, installing the local 1.6 artifact, rerunning all input smoke tests, and retaining the prior artifact until acceptance. Because this phase changes no Shadow Evidence transport and no persistent Claw schema, application rollback to 1.5 is supported after stopping analysis and verifying existing output remains intact.

No Windows support, complete protocol coverage, decryption, rule execution, or automatic enforcement is claimed.
