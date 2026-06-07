# frameseven

Offensive web security scanner — OWASP Top 10 active exploitation, real data extraction (SQLi multi-SGBD, SSRF, IDOR, A06 CVEs). CLI-first, no YAML required.

## Architecture

This project uses explicit versioned paths for tools and CLI entrypoints.

```text
tools/
  v1/
    example/
      example.go
      example.py

cmd/
  cli/
    v1/
      main.go
```

## Commands

Run the CLI:

```bash
go run cmd/cli/v1/main.go
```

Build the CLI:

```bash
go build -o bin/frameseven/cli/v1 cmd/cli/v1/main.go
```
