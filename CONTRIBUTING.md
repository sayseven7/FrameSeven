# Contributing to FrameSeven

Thank you for considering contributing to FrameSeven! This document outlines the guidelines and conventions we follow.

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md).

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
