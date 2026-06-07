# frameseven

Offensive web security scanner — OWASP Top 10 2025 active exploitation, real data
extraction (multi-DBMS SQLi, SSRF, IDOR, A06 CVEs). CLI-first, no YAML required,
standard library only.

## Architecture

The evolving offensive contract (the techniques whose payloads, behavior and output change
between versions) is versioned under `internal/tools/v1/`. Shared infrastructure (data
model, CVE enrichment, presentation, config) lives directly under `internal/`.

```text
internal/
  config/config.go                 # scan options + defaults + validation
  finding/finding.go               # Finding / Severity / Evidence data model
  cve/cve.go                       # version fingerprint -> NVD API 2.0 lookup
  report/report.go                 # Report struct, text (stdout) + JSON output
  tools/v1/
    recon/                         # DNS, headers, tech fingerprint, sensitive files, endpoints/params
    sqli/                          # boolean detection + UNION extraction (MySQL/MSSQL/PostgreSQL/SQLite)
    access/                        # unauthenticated endpoints + IDOR
    ssrf/                          # internal canary + cloud metadata (AWS/GCP/Azure)
    lfi/                           # local file inclusion + path traversal
    ratelimit/                     # request burst, status/latency variation
    misconfig/                     # security headers, dangerous methods, CORS, TLS
    scanner/                       # orchestrates recon + all modules -> report

cmd/cli/v1/main.go                 # CLI entrypoint
```

Each finding carries a proof of concept (request, response, extracted value), CVSS, CWE,
the OWASP Top 10 2025 category, and concrete next steps.

## Commands

Run the CLI:

```bash
go run cmd/cli/v1/main.go -url https://target.example
```

Write a JSON report alongside the text output:

```bash
go run cmd/cli/v1/main.go -url https://target.example -o report.json
```

Build the CLI:

```bash
go build -o bin/frameseven/cli/v1 cmd/cli/v1/main.go
```

### CLI flags v1

| Flag       | Default        | Description                                   |
|------------|----------------|-----------------------------------------------|
| `-url`     | (required)     | Target URL to scan                            |
| `-timeout` | `10s`          | Per-request timeout                           |
| `-rate`    | `50`           | Number of requests for the rate-limit test    |
| `-ua`      | `frameseven/v1`| User-Agent header                             |
| `-o`       | (none)         | Write the JSON report to this file            |

The NVD API key is read from the `NVD_API_KEY` environment variable (optional; raises the
CVE lookup rate limit).
```bash
NVD_API_KEY=xxxx go run cmd/cli/v1/main.go -url https://target.example
```
