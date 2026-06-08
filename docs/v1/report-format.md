# CLI Output Format v1

frameseven produces a human-readable report on standard output and writes
persistent reports to the output directory. The default directory is
`./reports` and can be changed with `-out` or `-o`.

## Output Files

| File | Description |
|---|---|
| `report.html` | Styled, self-contained browser report with expandable evidence |
| `report.md` | Portable human-readable report |
| `report.pdf` | Portable PDF report generated from the CLI v1 text report |
| `report.json` | Structured CLI output contract v1 |
| `scan.log` | Tool progress and optional request-level debug details |

Report files use restricted permissions because findings and evidence can
contain sensitive target data.

## JSON Contract

Every JSON report contains `"schema_version": "v1"`.

Top-level fields:

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Report contract version |
| `target` | string | Target URL supplied by the operator |
| `started_at` | string | Scan start time in RFC 3339-compatible JSON time format |
| `duration` | string | Rounded scan duration |
| `surface` | object | Attack surface collected by reconnaissance |
| `findings` | array | Findings sorted by severity |
| `errors` | array | Optional tool request errors |

## Surface

The `surface` object contains:

| Field | Type | Description |
|---|---|---|
| `base_url` | string | Original target URL |
| `host` | string | Target hostname |
| `headers` | object | Response headers from the initial request |
| `technologies` | array | Detected products, versions, and evidence sources |
| `dns` | object | Resolved A, CNAME, MX, NS, and TXT records |
| `endpoints` | array | Same-origin endpoints discovered in the initial page |
| `params` | array | Discovered parameter names, endpoints, and methods |
| `sensitive_files` | array | Sensitive paths confirmed by reconnaissance |

## Finding

Each finding can contain:

| Field | Type | Description |
|---|---|---|
| `title` | string | Short issue name |
| `module` | string | Module that produced the finding |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `owasp` | string | OWASP Top 10 2025 category |
| `cwe` | string | CWE identifier |
| `cvss` | number | CVSS score when available |
| `description` | string | Explanation of the issue |
| `evidence` | object | Request, response, and extracted proof |
| `next_steps` | array | Recommended follow-up actions |

The `evidence` object may contain `request`, `response`, and `extracted`
strings. Empty optional values are omitted from JSON.

## Tool Error

Errors do not discard successful results from other tools:

```json
{
  "module": "recon",
  "message": "network error details"
}
```

A report containing one or more tool errors is incomplete, and CLI v1 exits
with status `1`.

## Minimal Example

```json
{
  "schema_version": "v1",
  "target": "https://target.example",
  "started_at": "2026-01-01T12:00:00Z",
  "duration": "1.25s",
  "surface": {
    "base_url": "https://target.example",
    "host": "target.example",
    "headers": {},
    "technologies": [],
    "dns": {},
    "endpoints": [],
    "params": [],
    "sensitive_files": []
  },
  "findings": []
}
```
