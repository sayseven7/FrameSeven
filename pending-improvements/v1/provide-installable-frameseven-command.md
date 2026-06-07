# Provide an Installable frameseven Command

## Problem

The CLI v1 package is located at `cmd/cli/v1`. Running `go install` for that
package creates an executable named `v1` because Go derives the executable name
from the package directory.

Release archives and Debian packages provide a binary named `frameseven`, but
the project does not yet have a Go package entrypoint that installs that name
directly.

## Impact

The project cannot document a clean `go install` command without exposing the
wrong executable name or changing the current command structure. Users must
install a release artifact or build from source.

## Expected Correction

Provide a version-aware installation entrypoint that installs an executable
named `frameseven`, and update `docs/v1/installation.md` with the final
`go install` command.
