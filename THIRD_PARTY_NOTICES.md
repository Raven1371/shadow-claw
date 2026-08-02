# Third-party notices

Project-owned material is offered under PolyForm Noncommercial 1.0.0. Its
distributable applications include independent third-party components under
their own terms. PolyForm does not replace, narrow, or override those terms.

The machine-readable authority is
`licenses/DEPENDENCY_LICENSE_INVENTORY.json`. Platform builds augment it with an
artifact-specific `licenses/NATIVE_DEPENDENCY_INVENTORY.json` generated from
package-manager ownership and installed license evidence. A release build fails
if any redistributed ELF executable or shared library lacks attribution.

Core redistributed components include CPython (PSF-2.0), defusedxml (PSF-2.0),
PyYAML (MIT), openpyxl (MIT), et_xmlfile (MIT), PyInstaller bootloader/loader
(GPL-2.0-or-later with the PyInstaller bootloader exception), and platform
Graphviz packages (license determined from the exact Ubuntu or Rocky package,
not from the upstream filename). AppImageKit release 13 is build-only and is
licensed under MIT.

The `1.4.0.dev0` integration also uses the separately maintained Shadow Core
project under PolyForm Noncommercial 1.0.0 and its JSON Schema stack:
jsonschema, attrs, jsonschema-specifications, referencing, and rpds-py (MIT),
plus typing_extensions (PSF-2.0). No release artifact is published by this
development milestone; final redistribution payloads remain subject to the
existing license-evidence build gates.

Complete license texts copied from installed packages are stored below
`licenses/python`, `licenses/python-packages`, `licenses/pyinstaller`,
`licenses/graphviz`, `licenses/native-libraries`, and `licenses/appimage` when
applicable to the artifact.
