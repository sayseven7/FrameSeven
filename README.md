# frameseven

frameseven is a CLI-first offensive web security scanner for authorized
security testing. It maps a target's attack surface and runs active checks for
common web vulnerabilities and misconfigurations.

> Only scan systems that you own or have explicit permission to test.

## Requirements

- Go 1.26.4 or later in the Go 1.26 release line
- Git
- Network access to the authorized target
- Linux, macOS, or another environment supported by Go

## Development Setup

```bash
git clone https://github.com/sayseven7/frameseven.git
cd frameseven
go test ./...
go run cmd/cli/v1/main.go -url https://target.example
```

## Documentation

- [Documentation](docs/README.md)
- [Installation v1](docs/v1/installation.md)
- [CLI v1](docs/v1/cli.md)
- [MCP Server](docs/v1/mcp.md)
- [Report Format v1](docs/v1/report-format.md)
- [Contributing](CONTRIBUTING.md)
