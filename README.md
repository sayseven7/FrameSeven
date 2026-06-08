# frameseven

frameseven is a CLI-first offensive web security scanner for authorized
security testing. It maps a target's attack surface and runs active checks for
common web vulnerabilities and misconfigurations.

> Only scan systems that you own or have explicit permission to test.

## Requirements

- Go 1.26.4 or later in the Go 1.26 release line
- Python 3 with `fpdf2` for PDF report generation
- Git
- Network access to the authorized target
- Linux, macOS, or another environment supported by Go

## Development Setup

```bash
git clone https://github.com/sayseven7/frameseven.git
cd frameseven
python3 -m venv .venv
.venv/bin/python -m pip install "fpdf2>=2.8"
go test ./...
go run cmd/cli/v1/main.go -url https://target.example
```

PDF reports are rendered by the Go wrapper through Python. The wrapper uses
`FRAMESEVEN_PYTHON` when set, otherwise it looks for `.venv/bin/python`, then
falls back to `python3`. If Python or `fpdf2` is missing, PDF generation returns
a clear error instead of silently producing a broken report.

## Documentation

- [Documentation](docs/README.md)
- [Installation v1](docs/v1/installation.md)
- [CLI v1](docs/v1/cli.md)
- [MCP Server](docs/mcp.md)
- [Report Format v1](docs/v1/report-format.md)
- [Go Reference](https://pkg.go.dev/github.com/sayseven7/frameseven)
- [Contributing](CONTRIBUTING.md)
