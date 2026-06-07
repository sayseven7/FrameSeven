# AGENTS.md

## Goal

Keep changes simple, local, readable, and aligned with the current project.

---

## Rules

- Always prefer simple and explicit code.
- Avoid overengineering.
- Avoid unnecessary abstractions.
- Avoid generic systems unless clearly necessary.
- Prefer duplication over premature abstraction.
- Keep files small and focused.
- Keep functions straightforward.
- Prefer readability over cleverness.
- Only implement what was requested.
- Avoid unnecessary comments.
- Avoid excessive folder nesting.
- If something feels too complex, simplify it.
- Do not change unrelated code.
- Do not create architecture patterns without clear need.
- Prefer existing project conventions over introducing new ones.
- Avoid inline code like `if something return;`, always prefer block code like `if something { return }`.
- Avoid lines of code that are too close together, as this makes them difficult to read. Add space between some lines occasionally to improve readability.

---

## Command Rules

### Go

run: `go run cmd/cli/main.go`
build: `go build -o bin/frameseven/cli cmd/cli/main.go`
test: `go test -v ./...`
fmt: `go fmt ./...`

## Code Style

- Prefer simple local code.
- Create abstractions only when there is a real need.
- Avoid generic managers, premature factories, unnecessary interfaces, deep inheritance, and clever code.
- Use explicit block control flow.

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
