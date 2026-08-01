# Common standalone layout

Linux packaging scripts create a PyInstaller application directory, add a
launcher, examples, documentation, configuration, and a distro-native
Graphviz runtime. The launcher sets only bundle-relative Graphviz paths and
then executes the packaged analyzer; it performs no network access.

No license file is currently present in the authoritative repository. A
license is therefore not fabricated or inferred by packaging automation. The
repository owner must select/approve licensing before public distribution.
