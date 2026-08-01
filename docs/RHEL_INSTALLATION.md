# Rocky Linux and RHEL-compatible installation

For the portable archive, verify the SHA-256 inventory, extract it, then run:

```bash
./nmap-flow-analyzer-1.3.0-rc1-rhel-x64/nmap-flow-analyzer doctor
```

For the RPM:

```bash
sudo rpm -ivh nmap-flow-analyzer-1.3.0-rc1-rhel-x64.rpm
nmap-flow-analyzer preflight
```

Remove it with `sudo rpm -e nmap-flow-analyzer`. Use only RHEL artifacts built
and tested in the Rocky Linux 9 gate.
