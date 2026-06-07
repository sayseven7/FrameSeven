# Require Explicit Active Scan Mode

## Problem

Framework v1 runs active probes by default, including HTTP `PUT` and `DELETE` requests.

## Impact

A scan against a real application could modify or remove data when an endpoint accepts these methods.

## Expected Correction

Keep the default scan limited to non-destructive requests. Require an explicit CLI v1 option and clear operator confirmation before enabling probes that can change target state.
