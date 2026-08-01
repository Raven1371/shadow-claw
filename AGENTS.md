# Permanent Release Rules

## Compatibility

- Preserve approved Nmap and Zeek parsing, evidence correlation, confidence
  calculations, firewall candidates, manual-review decisions, schemas,
  deterministic identifiers, and evidence provenance.
- v1.2.5 is limited to analyzer-owned logging lifecycle, cross-platform test
  portability, version documentation, and the approved grammar correction.
- v1.3.0 must remain analyzer-equivalent to the verified v1.2.5 baseline.

## Security

- Never weaken scanner exclusion, traffic-state withholding, external
  dependency policy, sensor-health handling, No-Any/Any protection, policy
  scope, strict mode, atomic publication, rollback, stale cleanup, symlink and
  path containment, Graphviz timeouts, or report sanitization.
- Close only handlers owned by the current analyzer invocation. Never use
  `logging.shutdown()` as a reusable-library cleanup mechanism.
- Preflight performs no network access. Updates are explicit, HTTPS-only,
  bounded, verified, never automatically executed, and never replace a running
  executable.

## Testing

- Treat the full suite, offline runner, compilation, platform gates,
  compatibility comparisons, clean installation tests, and artifact smoke
  tests as mandatory.
- Environment-dependent skips must be narrow and state a precise reason.
- Do not proceed past a failed mandatory v1.2.5 or v1.3.0 gate.

## Packaging

- `pyproject.toml` is authoritative for v1.3.0 metadata and dependencies.
- Keep Windows, Ubuntu, and RHEL-compatible build families separate and
  reproducible, with onedir and onefile configurations for each.
- Bundle platform-appropriate Graphviz in standalone releases and include
  third-party notices.
- Never claim an executable, installer, archive, DEB, RPM, AppImage, wheel, or
  source distribution unless the file was produced and smoke-tested.
