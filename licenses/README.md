# Redistribution license payload

`DEPENDENCY_LICENSE_INVENTORY.json` records known source and build inputs.
Linux packaging adds `NATIVE_DEPENDENCY_INVENTORY.json`, exact Python package
metadata, and verbatim license files collected from the build environment.

Inventory evidence must be package metadata, package-manager ownership, or an
installed/upstream license document. Filenames alone are not evidence. An entry
whose `release_blocker` is true prohibits release. This inventory is engineering
evidence, not legal advice or legal certification.

The top-level PolyForm license applies only to project-owned material. License
texts under this directory belong to their identified third-party components,
including any legitimate Apache-2.0 files shipped by those components.
