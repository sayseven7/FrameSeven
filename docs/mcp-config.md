# MCP Client Configuration (HTTP)

This guide explains how to configure FrameSeven's MCP server in different
clients using Streamable HTTP. The MCP server exposes security scanning tools
that you can call directly from your AI coding assistant.

## Prerequisites

Run the MCP server over HTTP:

```bash
go run ./cmd/mcp -transport http -addr 127.0.0.1:8080
```

The endpoint will be available at:

```text
http://127.0.0.1:8080/mcp
```

Do not expose this server to the internet without access control — scanner tools
send active security probes to targets.

## Debugging with MCP Inspector

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector) is a
web-based tool for testing and debugging MCP servers interactively.

Run it with FrameSeven over stdio:

```bash
npx @modelcontextprotocol/inspector \
  go run ./cmd/mcp -transport stdio
```

Or point it to a running HTTP server:

```bash
npx @modelcontextprotocol/inspector
```

The Inspector opens a local web interface where you can browse available tools,
inspect their schemas, test calls with custom arguments, and view results and
logs.

## Configuration by Provider

### OpenCode

Add to `opencode.json`. The `timeout` value allows up to 10 minutes to connect
and fetch the server tools:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "frameseven": {
      "type": "remote",
      "url": "http://127.0.0.1:8080/mcp",
      "enabled": true,
      "timeout": 600000
    }
  }
}
```

OpenCode does not currently document a separate timeout for individual MCP tool
calls.

### Claude Code

Run this command from the project directory:

```bash
claude mcp add --transport http frameseven --scope project \
  http://127.0.0.1:8080/mcp
```

This creates or updates the project-level `.mcp.json`. The equivalent
configuration is:

```json
{
  "mcpServers": {
    "frameseven": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

Set a 5-minute timeout for each tool call and a 10-minute MCP startup timeout in
`~/.claude/settings.json` (global) or `./.claude/settings.json` (project):

```json
{
  "env": {
    "MCP_TOOL_TIMEOUT": "300000",
    "MCP_TIMEOUT": "600000"
  }
}
```

Both values are expressed in milliseconds. Restart Claude Code after changing
`settings.json`.

### Codex

Add to `~/.codex/config.toml` (global) or `./.codex/config.toml` (project in a
trusted workspace):

```toml
[mcp_servers.frameseven]
url = "http://127.0.0.1:8080/mcp"
tool_timeout_sec = 300
startup_timeout_sec = 600
```

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json` for the workspace. For user-level configuration, run
`MCP: Open User Configuration` from the Command Palette:

```json
{
  "servers": {
    "frameseven": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

VS Code does not currently document per-server MCP timeout fields in
`mcp.json`.

## Provider Documentation

- [OpenCode MCP servers](https://opencode.ai/docs/mcp-servers/)
- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Codex MCP](https://developers.openai.com/codex/mcp)
- [VS Code MCP servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
