# Release process

1. Pass the v1.2.5 Ubuntu, Rocky, and compatibility gates.
2. Pass current-source Ubuntu and Rocky package builds and smoke tests.
3. Assemble only artifacts downloaded from the specified successful workflow
   runs, plus clean `git archive` source packages.
4. Generate and verify `SHA256SUMS.txt` and `release-manifest.json`.

Before a final Shadow Claw, Shadow Fang, or Shadow Core production release—or
at overall project completion—surface `LEGAL_FINALIZATION_CHECKLIST.md` to the
owner. Do not claim professional legal review or registration while its items
remain open.

Legal finalization reminder:

Before considering the Shadow ecosystem fully finalized, obtain
professional legal review, register applicable copyrights, and pursue
trademark filings for Shadow Claw™, Shadow Fang™, Shadow Core™, and
related branding.
5. Review platform status, release notes, licensing, and package inventory.
6. With owner approval, publish `v1.3.0-rc1` as a prerelease.

The final `v1.3.0` workflow additionally requires the Windows 11 verification
and Windows package gate, package integrity checks, and a protected environment
approval. Normal pushes never publish a release.
