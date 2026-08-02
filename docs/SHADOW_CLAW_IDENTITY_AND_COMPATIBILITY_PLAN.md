# Shadow Claw Identity and Compatibility Plan

## Identity

The permanent product name is **Shadow Claw™**, and the repository identifier
is `shadow-claw` at `Raven1371/shadow-claw`. References to the former repository
name are updated when they are active metadata or instructions. Historical
release, validation, provenance, and third-party inventory records retain the
name and URLs that were accurate when those records were created.

## Compatibility contract

This preparation release does not remove or deprecate an identifier. The
following remain supported and unchanged:

- the `nmap-flow-analyzer` command;
- the `nmap_flow_analyzer` Python distribution, package, and import paths;
- command-line arguments and configuration formats;
- Nmap, Zeek, and other existing input formats;
- report schemas, filenames, identifiers, and deterministic behavior;
- validation, upgrade, and offline workflows; and
- published `v1.3.0-rc1` artifact names and historically accurate release
  documentation.

## Future command transition

A future, separately reviewed change may add `shadow-claw` as a second console
entry point backed by the same implementation as `nmap-flow-analyzer`. It must
include parity tests for help text, version output, exit status, arguments,
inputs, configuration, reports, and deterministic outputs before it can become
the documented primary command. The compatibility command will remain usable
throughout the transition.

Python package and import renaming is not planned. If it is ever proposed, the
existing distribution and import paths must remain complete aliases with
installation and import regression tests. No competing configuration, input,
or report format may be introduced solely for branding.

## Releases and semantic versioning

Development proceeds from `1.4.0.dev0`. Existing `v1.3.0-rc1` files are not
renamed. A future stable release may begin using `shadow-claw` for newly
published artifact names only after update, packaging, checksum, and rollback
tools accept both naming families. Changing the primary command or artifact
naming is a user-visible compatibility change and must be called out in release
notes; breaking removal requires a future major version.

## Documentation and deprecation policy

Documentation will initially show both names, identify Shadow Claw as the
product, and keep commands executable as written. Any future deprecation must:

1. be announced in release notes and command documentation;
2. provide an equivalent tested migration path;
3. last at least two stable minor releases and no less than 12 months; and
4. require explicit owner approval before removal.

Rollback must remain possible by restoring the former primary documentation
and entry-point preference without changing data formats or published assets.
If alias parity, packaging, update selection, or deterministic-output tests
fail, the new alias must not become primary.
