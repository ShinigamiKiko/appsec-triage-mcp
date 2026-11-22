"""Run with the mcp-agent virtualenv; all scanning happens through Docker MCP."""

from appsec_triage_mcp.client import main

if __name__ == "__main__":
    raise SystemExit(main())
