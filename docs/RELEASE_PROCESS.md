# Release process

1. Pass the v1.2.5 Ubuntu, Rocky, and compatibility gates.
2. Pass current-source Ubuntu and Rocky package builds and smoke tests.
3. Assemble only artifacts downloaded from the specified successful workflow
   runs, plus clean `git archive` source packages.
4. Generate and verify `SHA256SUMS.txt` and `release-artifacts.json`.
5. Review platform status, release notes, licensing, and package inventory.
6. With owner approval, publish `v1.3.0-rc1` as a prerelease.

The final `v1.3.0` workflow additionally requires the Windows 11 verification
and Windows package gate, package integrity checks, and a protected environment
approval. Normal pushes never publish a release.
