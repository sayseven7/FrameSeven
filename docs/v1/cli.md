# CLI Commands v1

## Command

Run the installed command:

```bash
frameseven [flags]
```

Run without flags in a terminal to open the interactive scan setup:

```bash
frameseven
```

For a development build that has not been installed:

```bash
./bin/frameseven/cli/v1 [flags]
```

## Flags

| Flag | Default | Description |
|---|---:|---|
| `-url` | required | Absolute HTTP or HTTPS target URL |
| `-timeout` | `10s` | Timeout applied to each HTTP request |
| `-rate` | `50` | Requests sent by the rate-limit module |
| `-ua` | `frameseven/v1` | User-Agent header sent by the scanner |
| `-o` | none | Path for an optional JSON report |
| `-interactive`, `-i` | disabled | Configure the scan with an interactive wizard |
| `-yes`, `-y` | disabled | Skip the wizard's final confirmation |
| `-quiet`, `-q` | disabled | Hide banner and progress messages |
| `-version` | disabled | Print the installed build version |
| `-list-modules` | disabled | List all Framework v1 scanner modules |

The target must include the scheme and host:

```bash
frameseven -url https://target.example
```

Values such as `target.example`, `ftp://target.example`, or an empty URL are
rejected.

## Interactive Mode

When standard input is a terminal and `-url` is omitted, CLI v1 starts an
interactive setup. It asks for:

- Target URL
- Per-request timeout
- Rate-limit request count
- User-Agent
- Optional JSON report path

The wizard displays the resulting configuration and requires confirmation
before starting because Framework v1 sends active security probes.

Start it explicitly:

```bash
frameseven --interactive
```

For authorized automated terminal sessions, `--yes` skips the final
confirmation. Interactive mode is rejected when standard input is not a
terminal.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `NVD_API_KEY` | No | NVD API key used by the CVE enrichment module |

## Examples

Set a longer request timeout:

```bash
frameseven \
  -url https://target.example \
  -timeout 30s
```

Change the rate-limit probe count:

```bash
frameseven \
  -url https://target.example \
  -rate 20
```

Set a custom User-Agent and write JSON:

```bash
frameseven \
  -url https://target.example \
  -ua "authorized-security-test/v1" \
  -o report.json
```

List the modules included in Framework v1:

```bash
frameseven --list-modules
```

Print the installed version:

```bash
frameseven --version
```

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | The scan completed without recorded module request errors |
| `1` | A module recorded a network error, or the JSON report could not be written |
| `2` | CLI configuration or flag validation failed |

Exit code `0` does not mean the target has no findings. Findings are reported
independently from command success.

## Network Behavior

- TLS certificate verification is disabled so the scanner can inspect targets
  with invalid certificates.
- Cross-origin redirects are blocked.
- Network failures are attached to the module that was running.
- Findings are sorted from highest to lowest severity.
