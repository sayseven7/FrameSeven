# Provide an Installable frameseven Command

## Problem

The CLI v1 package is located at `cmd/cli/v1`. Running `go install` for that
package creates an executable named `v1` because Go derives the executable name
from the package directory.

The project does not yet have a published, stable installation entrypoint that
produces a command named `frameseven`.

## Impact

The project cannot publish a clean `go install` command without exposing the
wrong executable name or changing the current command structure. Installation
documentation must continue to describe source builds until this is resolved.

## Expected Correction

Provide a version-aware installation entrypoint that installs an executable
named `frameseven`, publish the first versioned release, and update
`docs/v1/installation.md` with the final `go install` command.

