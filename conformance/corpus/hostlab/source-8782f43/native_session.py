"""Internal SQL literals and the owned bulk CLI session; external MCP is unchanged."""
from native_cli import CliSession as NativeSession


def literal(value):
    if any(c in value for c in "\r\n\0"):
        raise ValueError("audit SQL literal contains unsupported control characters")
    return "'" + value.replace("'", "''") + "'"


def in_list(values):
    return ",".join(literal(value) for value in values)
