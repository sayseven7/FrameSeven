# Placeholder External Tool Modules

## Problem

The `nmap` and `sqlmap` modules report only whether the corresponding binary is found in `PATH`. They do not execute the tools or integrate their output into the scan report.

## Impact

The module names suggest deeper integration than actually exists. An operator may enable these modules expecting Nmap or sqlmap to run as part of the scan and receive no actionable security results.

## Expected Correction

Implement actual external tool execution with:
- Configurable binary path and arguments
- Parsing of structured output (XML for Nmap, JSON for sqlmap)
- Mapping results back into Framework v1 findings
- Explicit operator confirmation before launching external processes
