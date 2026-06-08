# Contributing to FrameSeven

Thank you for considering contributing to FrameSeven! This document outlines the guidelines and conventions we follow.

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md).

## Language

Everything in the project must be written in English.

- This applies to code, documentation, comments, commit messages, CLI text, tests, issue descriptions, and AI-assisted changes.
- Contributors and AI agents must keep all new content in English.

## Versioning

Framework changes must be versioned for both code and documentation.

- Any framework-level code, public contract, reusable module, API shape, CLI contract, or shared structure must have an explicit version.
- This applies equally to human contributors and AI-assisted changes.
- Version identifiers must appear in folder structures whenever the change introduces or updates a public or evolving framework surface.
- The version format is fixed: use `v1`, `v2`, `v3`, and so on.
- The CLI must also follow this rule whenever it exposes commands, flags, input, output, config, or any other public contract.
- Documentation must name the version it describes.
- Do not replace an older version implicitly when adding a new one unless the change explicitly intends a migration or removal.
- Keep examples, paths, and docs synchronized with the implemented version.

### Folder Structure

```text
tools/v1/example/
cmd/cli/v1/
```

If a Go wrapper calls another implementation, keep the version visible in the same structure whenever that code is part of the framework surface.

## Development Dependencies

PDF report generation is implemented in Python and called through a Go wrapper.
Development environments must provide Python 3 and `fpdf2` locally:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install "fpdf2>=2.8"
```

The wrapper uses `FRAMESEVEN_PYTHON` when set, otherwise it looks for
`.venv/bin/python`, then falls back to `python3`. If Python is missing,
`fpdf2` is not installed, or the renderer fails, the Go wrapper must return an
error that identifies the problem.

## Pending Improvements

Problems identified by the team that still require correction are tracked in `pending-improvements/v1/`.

- Every file in the directory must be a Markdown file with the `.md` extension.
- Use a clear file name that identifies the specific problem.
- Clearly document the problem, its impact, and the expected correction.
- Add only confirmed problems identified by the team, not general ideas or feature requests.
- Remove the document after the correction has been implemented and verified.
- Use the directory version that matches the affected framework contract.

### Documentation

When documenting framework behavior, always mention the version in titles, sections, or examples.

Examples:

- `Framework API v1`
- `CLI commands v1`
- `Configuration schema v1`
- `Migration guide: v1 to v2`

## Commit Guidelines

We follow a structured commit format based on [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

The `scope` is optional and indicates which area of the project the change affects (e.g., `web`, `server`, `cli`, `api`).

### Types

| Type       | Description                                            | Example                                             |
|------------|--------------------------------------------------------|-----------------------------------------------------|
| `feat`     | Adds a new feature to the project                      | `feat(web): add image send button gating`           |
| `fix`      | Fixes an existing bug or issue                         | `fix(server): handle websocket disconnect cleanly`  |
| `refactor` | Restructures code without changing functionality       | `refactor(web): simplify webrtc peer lifecycle`     |
| `docs`     | Updates project documentation                          | `docs: update README for current stack`             |
| `style`    | Code style changes (formatting, indentation, etc.)     | `style(web): run prettier`                          |
| `test`     | Adds or modifies tests                                 | `test(server): cover jwt validation`                |
| `chore`    | Maintenance tasks not related to code                  | `chore: update project dependencies`                |
| `perf`     | Performance improvements                               | `perf(web): reduce rerenders in chat list`          |
| `revert`   | Reverts a previous change                              | `revert: revert changes in the controller`          |
| `ci`       | Changes to CI/CD configuration                         | `ci: update build pipeline`                         |

### Examples

```
feat(api): add user authentication endpoint
fix(cli): handle missing config file gracefully
refactor(web): extract message formatting utility
docs: add contribution guidelines
style: format go files with gofmt
test(server): add rate limiter tests
chore: bump golang version to 1.22
perf(db): optimize connection pooling
revert: revert user search pagination change
ci: add golangci-lint to pipeline
```

## Issues and Feature Requests

- Use [GitHub Issues](https://github.com/sayseven7/frameseven/issues) to report bugs or request features.
- Use [GitHub Discussions](https://github.com/sayseven7/frameseven/discussions) for questions, ideas, and general discussion.
- Search existing issues before opening a new one.
- For bugs, include steps to reproduce, expected behavior, and actual behavior.
- For features, describe the use case and proposed solution.
