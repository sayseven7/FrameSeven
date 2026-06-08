# MCP Server

FrameSeven includes a general MCP server at `cmd/mcp`. The server itself is not
versioned as a framework contract and can expose tools for multiple framework
versions. Tool names are versioned so clients can choose the exact tool
contract they are calling.

Run the server locally over stdin/stdout:

```bash
go run ./cmd/mcp -transport stdio
```

After installing a release archive:

```bash
frameseven-mcp
```

Run the server for remote agents over Streamable HTTP:

```bash
go run ./cmd/mcp -transport http -addr 127.0.0.1:8080
```

The MCP endpoint is:

```text
http://127.0.0.1:8080/mcp
```

Use `0.0.0.0:8080` only when the server is behind an access-controlled network,
reverse proxy, tunnel, or firewall rule. Scanner tools can send active security
probes, so do not expose this server openly to the internet.

## Tool Naming

The currently implemented tools expose Framework v1 contracts and use this
prefix:

```text
frameseven_v1_
```

## Available Tools

Metadata tools:

- `frameseven_v1_list_tools`: lists Framework v1 tools and default status.
- `frameseven_v1_normalize_tools`: validates and normalizes a tool list
  without starting a scan.

Scanner tools:

- `frameseven_v1_recon`
- `frameseven_v1_sqli`
- `frameseven_v1_access`
- `frameseven_v1_ssrf`
- `frameseven_v1_lfi`
- `frameseven_v1_misconfig`
- `frameseven_v1_ratelimit`
- `frameseven_v1_cve`
- `frameseven_v1_crawler`
- `frameseven_v1_content`
- `frameseven_v1_subdomain`
- `frameseven_v1_ports`
- `frameseven_v1_nmap`
- `frameseven_v1_sqlmap`
- `frameseven_v1_bannergrab`

Every scanner tool requires `active_scan_accepted: true` because it may send
active security probes to the target.

## Scanner Tool Input

Scanner tools accept:

```json
{
  "target": "https://target.example",
  "active_scan_accepted": true,
  "timeout_seconds": 10,
  "tool_timeout_seconds": 30,
  "concurrency": 1,
  "rate_requests": 50,
  "user_agent": "frameseven/v1",
  "nvd_api_key": "",
  "extra_tools": [],
  "custom_payloads": []
}
```

`custom_payloads` is optional. It is capped at 25 entries, each entry is capped
at 300 characters, and unsupported tools ignore it. Framework API v1 tools that
currently use custom payloads are:

- `frameseven_v1_sqli`: appends each custom payload to discovered parameter
  values and reports suspicious SQL error, server error, or large response
  changes for manual verification.
- `frameseven_v1_lfi`: injects each custom payload into file-like parameters
  and reports only when known local-file signatures are returned.
- `frameseven_v1_ssrf`: injects each custom payload into URL-like parameters
  and reports only when known metadata-service signatures are returned.
- `frameseven_v1_content`: treats each custom payload as an additional
  same-target content path. Absolute URLs are ignored.
- `frameseven_v1_access`: treats each custom payload as an additional
  same-target sensitive endpoint path. Absolute URLs are ignored.
- `frameseven_v1_subdomain`: treats each custom payload as an additional DNS
  label under the target root domain. Invalid labels are ignored.

Custom payloads do not execute shell commands or external programs. They are
only inserted into the existing Framework API v1 scanner flows.

## Timeouts

`timeout_seconds` is the per-request timeout. `tool_timeout_seconds` is the
maximum runtime for each selected Framework API v1 scanner tool before the scan
records a tool error and continues. `concurrency` controls how many independent
scanner tools run in parallel after `recon`.

Slow full scans can still hit the MCP client's tool-call timeout
(`operation timed out`). Raise the client timeout when the whole scan needs more
time. In Claude Code, set it in `settings.json` `env` (applied on restart):

```json
{
  "env": {
    "MCP_TOOL_TIMEOUT": "600000",
    "MCP_TIMEOUT": "120000"
  }
}
```

`MCP_TOOL_TIMEOUT` bounds each tool call; `MCP_TIMEOUT` bounds server startup
(both in milliseconds).

## Output

Scanner tools return a summarized report containing:

- framework version
- target
- requested tool
- selected tools
- duration
- finding count
- error count
- summarized findings
- tool errors

Use the CLI report files when a full HTML, Markdown, or JSON scan report is
needed.
