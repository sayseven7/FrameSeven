# Getting Started with Framework v1

Install frameseven before continuing:

- [Installation v1](installation.md)

## Run a Scan

Run the installed command without flags to configure the scan interactively:

```bash
frameseven
```

For scripts and repeatable commands, provide the target directly:

```bash
frameseven -url https://target.example
```

The command writes a human-readable summary to standard output, tool
progress to standard error, and persistent results to `./reports`.

## Generated Reports

Every scan creates:

- `reports/report.html`: styled, self-contained report for browsers
- `reports/report.md`: portable Markdown report
- `reports/report.pdf`: portable PDF report
- `reports/report.json`: machine-readable CLI output format v1
- `reports/scan.log`: execution progress and diagnostic messages

Use `-out` or `-o` to select another directory:

```bash
frameseven \
  -url https://target.example \
  -out audit-results
```

The JSON document includes `"schema_version": "v1"`.

Use `--verbose` when diagnosing a scan. It adds HTTP request, response,
duration, and network error details to the terminal and `scan.log`.

Library callers can provide a standard `*log.Logger` through `config.Config`.
Set `Config.Verbose` to include request-level HTTP diagnostics.

## NVD API Key

The CVE tool can query the NVD API without a key, but a key raises the API
rate limit.

```bash
NVD_API_KEY=your-key frameseven -url https://target.example
```

## Framework v1 Scan Pipeline

Framework v1 runs selected tools in this order. The first eight tools are selected by default. The remaining official tools run when selected explicitly or through `-tools all`:

1. `recon`: resolves DNS, fingerprints technologies, discovers endpoints and
   parameters, and probes known sensitive paths.
2. `sqli`: tests discovered parameters for SQL injection and attempts database
   fingerprinting and data extraction.
3. `access`: checks unauthenticated administrative paths and possible IDOR
   behavior.
4. `ssrf`: tests likely URL parameters with internal and cloud metadata
   targets.
5. `lfi`: tests likely file parameters for local file inclusion and path
   traversal.
6. `misconfig`: checks headers, HTTP methods, CORS, and TLS configuration.
7. `ratelimit`: sends a request burst and observes status and latency changes.
8. `cve`: looks up CVEs for technologies with detected versions.
9. `crawler`: visits known same-origin endpoints and extracts additional links.
10. `content`: checks a small seed list of common content paths.
11. `subdomain`: resolves common subdomain candidates.
12. `ports`: checks common web-facing TCP ports.
13. `nmap`: runs an Nmap scan of common web-facing ports and reports the open ones. If Nmap is missing or the run fails, it degrades to an informational finding instead of blocking the scan.
14. `sqlmap`: runs a sqlmap SQL injection test against the target URL and reports any confirmed injection. If sqlmap is missing or the run fails, it degrades to an informational finding instead of blocking the scan.
15. `bannergrab`: checks lightweight FTP, SSH, and SMTP service banners.

## Safety Notice

Use Framework v1 only against systems you are authorized to test.

The current v1 implementation performs active probes. The misconfiguration
tool may send `PUT` and `DELETE` requests, and the SQL injection tool may
attempt data extraction. These requests can affect application state on an
unsafe target.

Known limitations are tracked in
[`pending-improvements/v1/`](../../pending-improvements/v1/README.md).
