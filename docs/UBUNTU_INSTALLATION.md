# Ubuntu installation

For the portable archive, verify the SHA-256 inventory, extract it, then run:

```bash
./nmap-flow-analyzer-1.3.0-rc1-ubuntu-x64/nmap-flow-analyzer doctor
```

For the DEB:

```bash
sudo dpkg -i nmap-flow-analyzer-1.3.0-rc1-ubuntu-x64.deb
nmap-flow-analyzer preflight
```

Remove the DEB with `sudo dpkg -r nmap-flow-analyzer`. AppImage instructions
apply only when a verified `.AppImage` is included in the release inventory.
