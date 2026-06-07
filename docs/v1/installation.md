# Installation v1

## Distribution Status

Versioned binaries and Linux packages are published through
[GitHub Releases](https://github.com/sayseven7/frameseven/releases).

GitHub Releases is the official distribution channel. Use a release artifact
or build the project from source for development.

Each release provides:

- CLI and MCP Linux binaries for `amd64` and `arm64`
- CLI and MCP macOS binaries for `amd64` and `arm64`
- CLI and MCP Windows binaries for `amd64`
- Debian packages for `amd64` and `arm64`
- RPM packages for `amd64` and `arm64`
- Arch Linux packages for `amd64` and `arm64`
- A `SHA256SUMS` file for artifact verification

Release tags use the `vX.Y.Z` format. Artifact and package versions omit the
leading `v`.

Release assets follow this naming convention:

```text
frameseven_<component>_<version>_<os>_<arch>.<format>
```

The component is `cli` or `mcp`. Linux packages currently install the CLI
binary and therefore use the `cli` component.

The public operating system names are `linux`, `macos`, and `windows`.

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
sudo apt install ./frameseven_cli_<version>_linux_amd64.deb
```

Use the `arm64` package instead when running a 64-bit ARM system.

Verify the installation:

```bash
frameseven -h
```

## Red Hat, Fedora, and RPM-Based Distributions

Download the `.rpm` file for your architecture from the release page, then
install it:

```bash
sudo dnf install ./frameseven_cli_<version>_linux_amd64.rpm
```

Use the `arm64` package instead when running a 64-bit ARM system.

## Arch Linux

Download the `.pkg.tar.zst` file for your architecture from the release page,
then install it:

```bash
sudo pacman -U ./frameseven_cli_<version>_linux_amd64.pkg.tar.zst
```

Use the `arm64` package instead when running a 64-bit ARM system.

## Linux and macOS Archive

Download the archive for your operating system and architecture, extract it,
and install the binary in a directory included in `PATH`:

```bash
tar -xzf frameseven_cli_<version>_linux_amd64.tar.gz
sudo install -m 0755 \
  frameseven_cli_<version>_linux_amd64/frameseven-cli \
  /usr/local/bin/frameseven
```

For the MCP server, download the `mcp` archive instead:

```bash
tar -xzf frameseven_mcp_<version>_linux_amd64.tar.gz
sudo install -m 0755 \
  frameseven_mcp_<version>_linux_amd64/frameseven-mcp \
  /usr/local/bin/frameseven-mcp
```

## Windows Archive

Download and extract the Windows `.zip` file from the release page. Add the
directory containing `frameseven-cli.exe` or `frameseven-mcp.exe` to `PATH`.

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
go build -o bin/frameseven/mcp cmd/mcp/main.go
```

Run the built command:

```bash
./bin/frameseven/cli/v1 -url https://target.example
```

Run the MCP server over stdin/stdout:

```bash
./bin/frameseven/mcp
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
