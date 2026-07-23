# Zeek Collection Guide

This guide explains how to produce Zeek logs that the analyzer can ingest
with `--zeek-dir`. The analyzer itself is strictly a **read-only analysis
tool**: it never captures traffic, never runs `zeek -i`, and never makes
network connections. You collect the logs; the analyzer only reads them.

> **Authorization required.** Live packet capture records the contents and
> metadata of other people's communications. Perform captures only on
> networks you own or where you have explicit written authorization, and
> follow your organization's data-handling and retention policies.

## 1. Processing an authorized PCAP with Zeek (recommended start)

If you already have an authorized capture file, process it offline:

```sh
mkdir zeek-logs
cd zeek-logs
zeek -r /path/to/authorized-capture.pcap LogAscii::use_json=T
```

`LogAscii::use_json=T` produces JSON Lines logs (`conn.log`, `dns.log`,
`ssl.log`, ...), which are the easiest format to move around. The included
helper script wraps this safely:

```sh
python3 scripts/zeek_process_pcap.py --pcap /path/to/capture.pcap --output-dir ./zeek-logs
```

The helper only processes an **existing** capture file — it does not and
cannot capture live traffic.

## 2. Persistent JSON logs on a sensor (`local.zeek`)

For an ongoing sensor deployment, enable JSON output in
`$PREFIX/share/zeek/site/local.zeek`:

```zeek
@load policy/tuning/json-logs.zeek
```

or equivalently:

```zeek
redef LogAscii::use_json = T;
```

then redeploy (`zeekctl deploy`). Rotated logs
(e.g. `conn.2026-07-20-01-00-00.log.gz`) are supported directly.

## 3. Native TSV logs

JSON is not required. The analyzer parses native Zeek TSV logs, including
their `#separator`, `#fields`, `#types`, `#empty_field`, and `#unset_field`
headers, and gzip-compressed rotations. Directories may even mix formats.

## 4. Copying logs into an analyzer input directory

Copy (do not symlink — symbolic links are deliberately not followed) the
logs into one or more directories and point the analyzer at them:

```sh
mkdir -p ./zeek-input
cp /opt/zeek/logs/2026-07-20/conn*.log.gz ./zeek-input/
cp /opt/zeek/logs/2026-07-20/{dns,ssl,http,dhcp,capture_loss,reporter}*.log.gz ./zeek-input/ 2>/dev/null || true

nmap-flow-analyzer --input scan.xml --config network_config.yaml \
    --zeek-dir ./zeek-input --output-dir ./analysis
```

`conn.log` is required for Zeek analysis; every other log is optional
enrichment. Include `capture_loss.log` and `reporter.log` whenever you can:
without capture-loss data the sensor's health is reported as *unknown*,
never assumed healthy.

## 5. Recommended collection windows

- Cover at least one full business cycle (24h minimum; 7 days is much
  better) so scheduled and periodic dependencies appear.
- Note the window's start and end; the report correlates it with the Nmap
  scan time and flags conflicts between the two.
- Month-end, quarter-end, and maintenance-window dependencies may only
  appear in longer windows.

## 6. Sensor placement and visibility limitations

A passive sensor sees **only the traffic that reaches it**:

- **Placement:** a sensor on a core span sees inter-VLAN traffic but may
  miss traffic switched locally within an access switch.
- **Virtual switches / same-host VMs:** traffic between two VMs on the same
  hypervisor or the same virtual switch typically never reaches a physical
  tap. Use hypervisor-level mirroring if that traffic matters.
- **Packet loss:** an oversubscribed span port silently drops packets.
  Watch `capture_loss.log`; the analyzer marks the sensor *degraded* above
  the configured threshold and lowers confidence (it never deletes observed
  flows).
- **Encrypted traffic:** Zeek records TLS metadata (SNI, versions,
  certificates) but does not inspect encrypted content, and this analyzer
  never claims otherwise.

## 7. Interpreting absence correctly

**Lack of observed traffic is not proof that a dependency is unnecessary.**
A service with no traffic during the window may be seasonal, disaster-
recovery-only, or simply outside the sensor's view. The analyzer therefore
labels such services "Not observed during the Zeek collection window" and
never "unused" or "safe to remove".
