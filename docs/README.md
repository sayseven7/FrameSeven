# frameseven Documentation

frameseven is a CLI-first offensive web security scanner. It maps a target's
attack surface and runs active checks for common web vulnerabilities and
misconfigurations.

## Current Version

The current framework and CLI contract is v1.

- [Installation v1](v1/installation.md)
- [Getting Started with Framework v1](v1/getting-started.md)
- [CLI Commands v1](v1/cli.md)
- [CLI Output Format v1](v1/report-format.md)

## Distribution Status

Installable releases have not been published yet. Until the first release,
build frameseven from source by following [Installation v1](v1/installation.md).

The intended public product is the `frameseven` command. The Go implementation
packages currently live under `internal/` and are not an importable library
API.

## Responsible Use

Only scan systems that you own or have explicit permission to test. Framework
v1 performs active requests and may send methods or payloads that affect a
target application.
