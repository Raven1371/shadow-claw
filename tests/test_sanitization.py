"""Unit tests for spreadsheet sanitization and output-format escaping."""

from nmap_flow_analyzer.sanitization import (
    escape_dot_label,
    escape_html,
    escape_markdown_inline,
    escape_mermaid_label,
    sanitize_row,
    sanitize_spreadsheet_value,
)

DANGEROUS = ["=1+1", "+SUM(A1:A2)", "-CMD()", '@HYPERLINK("example")', " =1+1"]


def test_dangerous_values_are_prefixed():
    for value in DANGEROUS:
        out = sanitize_spreadsheet_value(value)
        assert out == "'" + value
        assert not out.startswith(("=", "+", "-", "@"))


def test_leading_whitespace_variants_are_caught():
    for value in ("\t=1+1", "  +SUM(A1)", "\n-2+3", "\r@cmd"):
        assert sanitize_spreadsheet_value(value).startswith("'")


def test_benign_values_are_untouched():
    for value in (
        "192.168.10.30",          # IP address
        "192.168.10.0/24",        # CIDR
        "2001:db8::30",           # IPv6
        "2026-07-01 10:00:00",    # timestamp
        "1024-65535",             # port range (starts with digit)
        '{"key": "value"}',       # JSON payload
        "normal text",
        "",
    ):
        assert sanitize_spreadsheet_value(value) == value


def test_non_string_values_pass_through():
    # Genuinely numeric negatives must remain numeric.
    assert sanitize_spreadsheet_value(-42) == -42
    assert sanitize_spreadsheet_value(-3.5) == -3.5
    assert sanitize_spreadsheet_value(None) is None
    assert sanitize_spreadsheet_value(True) is True


def test_sanitize_row_respects_toggle():
    row = {"a": "=1+1", "b": 5}
    assert sanitize_row(row, enabled=True)["a"] == "'=1+1"
    assert sanitize_row(row, enabled=False)["a"] == "=1+1"
    assert sanitize_row(row, enabled=True)["b"] == 5


def test_html_escape():
    assert escape_html("<script>alert(1)</script>") == (
        "&lt;script&gt;alert(1)&lt;/script&gt;"
    )
    assert '"' not in escape_html('a"b')


def test_dot_label_escape_neutralizes_injection():
    hostile = 'host"; A -> B; "'
    out = escape_dot_label(hostile)
    assert '\\"' in out and '";' not in out.replace('\\"', "")
    for ch in "{}|<>":
        assert "\\" + ch in escape_dot_label(f"a{ch}b")
    assert "\\n" in escape_dot_label("line1\nline2")
    assert "\n" not in escape_dot_label("line1\nline2")


def test_mermaid_label_escape_neutralizes_injection():
    hostile = "node] --> attacker"
    out = escape_mermaid_label(hostile)
    assert "]" not in out and "#93;" in out
    out2 = escape_mermaid_label('a"b|c[d')
    for ch in '"|[':
        assert ch not in out2
    assert "<br/>" in escape_mermaid_label("line1\nline2")


def test_markdown_escape_preserves_tables_and_html():
    assert "\\|" in escape_markdown_inline("value|new-column")
    assert "&lt;script&gt;" in escape_markdown_inline("<script>alert(1)</script>")
    assert "\n" not in escape_markdown_inline("line1\nline2")
