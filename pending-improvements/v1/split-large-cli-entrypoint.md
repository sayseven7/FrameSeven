# Split Large CLI Entrypoint

## Problem

The CLI v1 entrypoint currently handles flag parsing, interactive prompts, module selection, banner output, logging setup, scan execution, and report writing in one file.

## Impact

The file is harder to review and maintain as CLI behavior grows. Small changes to prompts, flags, banners, or report output all touch the same entrypoint, increasing review noise and the chance of accidental regressions.

## Expected Correction

Keep the CLI package simple, but split focused helpers into small files such as `banner.go`, `modules.go`, and `wizard.go`. Do not introduce a generic command framework unless the CLI genuinely needs it.
