# Installation v1

## Distribution Status

Versioned binaries and Debian packages are published through
[GitHub Releases](https://github.com/sayseven7/frameseven/releases).

Installation through `go install` is not supported yet. Use a release artifact
or build from source.

Each release provides:

- Linux binaries for `amd64` and `arm64`
- macOS binaries for `amd64` and `arm64`
- A Windows binary for `amd64`
- Debian packages for `amd64` and `arm64`
- A `SHA256SUMS` file for artifact verification

Release tags use the `vX.Y.Z` format. Artifact and Debian package versions omit
the leading `v`.

## Requirements

- A supported Linux, macOS, or Windows system
- Network access to the authorized scan target

Building from source additionally requires Git and Go 1.26.4 or later in the
Go 1.26 release line.

## Debian and Ubuntu

Download the `.deb` file for your architecture from the
[release page](https://github.com/sayseven7/frameseven/releases), then install
it:

```bash
sudo apt install ./frameseven_<version>_amd64.deb
```

Use the `arm64` package instead when running a 64-bit ARM system.

Verify the installation:

```bash
frameseven -h
```

## Linux and macOS Archive

Download the archive for your operating system and architecture, extract it,
and install the binary in a directory included in `PATH`:

```bash
tar -xzf frameseven_<version>_linux_amd64.tar.gz
sudo install -m 0755 \
  frameseven_<version>_linux_amd64/frameseven \
  /usr/local/bin/frameseven
```

## Windows Archive

Download and extract the Windows `.zip` file from the release page. Add the
directory containing `frameseven.exe` to `PATH`.

## Verify a Download

Download `SHA256SUMS` alongside the selected artifact:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

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

## Install a Development Build

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

This installs a local development build instead of a versioned release
artifact.

## Optional NVD API Key

The CVE module can use an NVD API key to increase the API request limit:

```bash
export NVD_API_KEY=your-key
```

The key is optional and is read at runtime.
