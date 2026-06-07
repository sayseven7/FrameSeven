# Getting Started with Framework v1

Install frameseven before continuing:

- [Installation v1](installation.md)

## Run a Scan

Use the installed command:

```bash
frameseven -url https://target.example
```

The command writes the human-readable report to standard output and progress
or error messages to standard error.

## Write a JSON Report

```bash
frameseven \
  -url https://target.example \
  -o report.json
```

The JSON document uses the CLI output format v1 and includes
`"schema_version": "v1"`.

## NVD API Key

The CVE module can query the NVD API without a key, but a key raises the API
rate limit.

```bash
NVD_API_KEY=your-key frameseven -url https://target.example
```

## Framework v1 Scan Pipeline

Framework v1 runs these modules in order:

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

## Safety Notice

Use Framework v1 only against systems you are authorized to test.

The current v1 implementation performs active probes. The misconfiguration
module may send `PUT` and `DELETE` requests, and the SQL injection module may
attempt data extraction. These requests can affect application state on an
unsafe target.

Known limitations are tracked in
[`pending-improvements/v1/`](../../pending-improvements/v1/README.md).
