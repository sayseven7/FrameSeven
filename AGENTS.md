# AGENTS.md

## Goal

Keep changes simple, local, readable, and aligned with the current project.

---

## Rules

- Everything in the project must be written in English.
- This applies to code, documentation, comments, commit messages, CLI text, tests, and AI-generated content.
- Avoid overengineering.
- Avoid unnecessary abstractions.
- Avoid generic systems unless clearly necessary.
- Prefer duplication over premature abstraction.
- Only implement what was requested.
- Avoid excessive folder nesting.
- If something feels too complex, simplify it.
- Do not change unrelated code.
- Do not create architecture patterns without clear need.
- Prefer existing project conventions over introducing new ones.
- The project will use Go, but if by chance there is a better implementation, for example in Python, implement it following this architecture:

│   └── tools
│       └── v1
│           └── example
│               ├── example.go
│               ├── example.py
│               ├── example_test.go
│               └── example_test.py

And use Go as a wrapper to call this function.

---

## Versioning

- The framework must always be versioned.
- Any new framework implementation, module, contract, or public structure must carry an explicit version.
- The CLI must also be versioned when it exposes commands, flags, input, output, config, or any other public contract.
- Versioning must appear in both folder structure and documentation.
- Do not use generic paths for framework code that is part of a public or evolving contract.
- The version format is fixed: use `v1`, `v2`, `v3`, and so on.
- When adding a new version, do not silently replace the old one unless that was explicitly requested.
- Keep docs, examples, commands, and references aligned with the version that is actually implemented.

```text
tools/
  v1/
    example/
      example.go
      example.py
```

```text
cmd/
  cli/
    v1/
```

Documentation must also reference the version explicitly, for example:

- `Framework API v1`
- `CLI commands v1`
- `CLI output format v1`
- `Migration from v1 to v2`

---

## Command Rules

### Go

run: `go run cmd/cli/v1/main.go`
build: `go build -o bin/frameseven/cli/v1 cmd/cli/v1/main.go`
test: `go test -v ./...`
fmt: `go fmt ./...`
vet: `go vet ./...`

## Code Style

- Always prefer simple and explicit code.
- Keep files small and focused.
- Keep functions straightforward.
- Prefer readability over cleverness.
- Avoid unnecessary comments.
- Create abstractions only when there is a real need.
- Avoid generic managers, premature factories, unnecessary interfaces, deep inheritance, and clever code.
- Use explicit block control flow.
- Avoid inline code like `if something return;`, always prefer block code like `if something { return }`.
- Avoid lines of code that are too close together, as this makes them difficult to read. Add space between some lines occasionally to improve readability.

Prefer:

```python
if not target:
    return None
```

Avoid:

```python
if not target: return None
```

- Use blank lines to separate logical steps, not every line.

---

## Testing Targets

Intentionally vulnerable sites that can be used as a base to test the tool:

- http://testaspnet.vulnweb.com/ (Acunetix demo, ASP.NET / MSSQL)
- https://preview.owasp-juice.shop/ (OWASP Juice Shop)
