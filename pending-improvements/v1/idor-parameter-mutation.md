# IDOR Parameter Mutation Without Confirmation

## Problem

The `access` module's IDOR check (`access.go:probeIDOR`) mutates numeric parameter values by sending requests with incremented and decremented identifiers. These requests reach the target and can trigger state changes, such as viewing or modifying another user's data.

## Impact

An operator scanning a production system may unknowingly access or expose data belonging to other users. The check does not distinguish between read-only and write operations, and it does not warn the operator before mutating identifiers.

## Expected Correction

- Treat IDOR probing as an active/destructive scan technique
- Require explicit opt-in (flag or wizard confirmation) before enabling parameter mutation
- Add documentation that explains the risk of IDOR testing on production systems
