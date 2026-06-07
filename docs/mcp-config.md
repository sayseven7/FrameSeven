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

### opencode

Add to `opencode.json`:

```json
{
  "mcpServers": {
    "frameseven": {
      "type": "url",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

### Claude Code

Add to `~/.claude/settings.json` (global) or `./.claude/settings.json`
(project):

```json
{
  "mcpServers": {
    "frameseven": {
      "type": "url",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

### Codex

Add to `~/.codex/settings.json` (global) or `./.codex/settings.json`
(project):

```json
{
  "mcpServers": {
    "frameseven": {
      "type": "url",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json` (workspace) or `~/.vscode/mcp.json` (global):

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
