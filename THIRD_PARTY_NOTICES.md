# Third-party notices

This project is Apache-2.0 licensed, but its distributable applications include
independent third-party components under their own terms. Nothing in the project
license changes those terms.

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

Complete license texts copied from installed packages are stored below
`licenses/python`, `licenses/python-packages`, `licenses/pyinstaller`,
`licenses/graphviz`, `licenses/native-libraries`, and `licenses/appimage` when
applicable to the artifact.
