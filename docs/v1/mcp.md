# MCP Server

FrameSeven includes a general MCP server at `cmd/mcp`. The server itself is not
versioned as a framework contract and can expose tools for multiple framework
versions. Tool names are versioned so clients can choose the exact tool
contract they are calling.

Run the server over stdin/stdout:

```bash
go run ./cmd/mcp
```

After installing a release archive:

```bash
frameseven-mcp
```

## Tool Naming

The currently implemented tools expose Framework v1 contracts and use this
prefix:

```text
frameseven_v1_
```

## Available Tools

Metadata tools:

- `frameseven_v1_list_modules`: lists Framework v1 modules and default status.
- `frameseven_v1_normalize_modules`: validates and normalizes a module list
  without starting a scan.

Module tools:

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

Every module tool requires `active_scan_accepted: true` because it may send
active security probes to the target.

## Module Tool Input

Module tools accept:

```json
{
  "target": "https://target.example",
  "active_scan_accepted": true,
  "timeout_seconds": 10,
  "rate_requests": 50,
  "user_agent": "frameseven/v1",
  "nvd_api_key": "",
  "extra_modules": []
}
```

## Output

Module tools return a summarized report containing:

- framework version
- target
- requested module
- selected modules
- duration
- finding count
- error count
- summarized findings
- module errors

Use the CLI report files when a full HTML, Markdown, or JSON scan report is
needed.
