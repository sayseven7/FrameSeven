# How to Create a Pending Improvement Report

This directory documents confirmed problems in the framework that the team has identified and still needs to correct. Each problem must be filed under the version it affects (`v1/`, `v2/`, etc.).

## File Location

Place your report in the version directory:

```
pending-improvements/
  v1/
    your-descriptive-file-name.md
```

## Naming Convention

Use lowercase, hyphen-separated names that clearly describe the problem.

Examples: `reduce-http-200-false-positives.md`, `split-large-cli-entrypoint.md`

## Required Structure

Every report must contain exactly three sections in this order:

```markdown
# Short Title

## Problem

Describe the current behavior or design that is problematic.

## Impact

Explain what can go wrong. Be specific about the consequences.

## Expected Correction

Describe the desired fix or improvement in concrete terms.
```

## Rules

- Write everything in English.
- Keep the file focused on a single problem.
- Describe the problem, its impact, and the expected correction clearly.
- Remove the file once the correction has been implemented and verified.
- Do not use this directory for general ideas, feature requests, or completed work.

## Example

See `v1/reduce-http-200-false-positives.md` and the other existing files in `v1/`.
