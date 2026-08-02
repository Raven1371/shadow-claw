# Linux-First Platform Policy

## Platform status

Supported active development:

- Ubuntu 24.04 x64
- Rocky Linux 9 / RHEL-compatible x64

Deferred:

- Windows 11 x64

Windows validation, packaging, and application integration are deferred
to a later dedicated development phase.

The Linux-first development strategy must not be represented as validated
Windows support or as a fully cross-platform production release.

Deferred Windows work does not block Linux development. Existing Windows
compatibility code, documentation, tests, and workflows should be preserved
where practical and must not be deleted solely because validation is deferred.

Shared components remain platform-neutral: schemas, evidence formats,
identifiers, timestamps, normalized event structures, compatibility metadata,
APIs, path representations, package manifests, and provenance records.
Operating-system-specific behavior belongs behind platform adapters. Shared
logic must avoid unnecessary hard-coded Linux paths.

Platform claims require validation on the named platform. Linux-first status
does not imply that the ecosystem integration or a cross-platform production
release is complete.
