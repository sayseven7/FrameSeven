# Installation v1

## Distribution Status

Installable frameseven releases are not published yet. The current supported
method is to build the CLI from source.

The release distribution will provide a command named `frameseven`. This page
will contain the final package and `go install` commands after the stable
installation entrypoint and the first v1 release are published.

## Requirements

- Go 1.26.4 or later in the Go 1.26 release line
- Git
- Linux, macOS, or another environment supported by Go

## Build from Source

```bash
git clone https://github.com/sayseven7/frameseven.git
cd frameseven
go test ./...
go build -o bin/frameseven/cli/v1 cmd/cli/v1/main.go
```

Run the built command:

```bash
./bin/frameseven/cli/v1 -url https://target.example
```

## Install the Development Build

Install the current build as `frameseven` in a directory already included in
your `PATH`:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 bin/frameseven/cli/v1 "$HOME/.local/bin/frameseven"
```

Verify the command:

```bash
frameseven -h
```

This installs a local development build. It is not a substitute for a
versioned release package.

## Optional NVD API Key

The CVE module can use an NVD API key to increase the API request limit:

```bash
export NVD_API_KEY=your-key
```

The key is optional and is read at runtime.
