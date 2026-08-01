# Graphviz bundling

Linux standalone packages bundle the Graphviz executable, plugins, and needed
non-system libraries. Discovery order is:

1. explicitly configured path;
2. bundled Graphviz;
3. system `PATH`;
4. standard installation paths.

`doctor` and `preflight` report the selected source and perform bounded SVG and
PNG renders. Merely running `dot -V` is not considered sufficient. If Graphviz
is unavailable, DOT and Mermaid sources remain available and image rendering
degrades gracefully.
