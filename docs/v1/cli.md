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
| `-rate` | `50` | Requests sent by the rate-limit tool |
| `-ua` | `frameseven/v1` | User-Agent header sent by the scanner |
| `-out`, `-o` | `reports` | Directory for generated reports and the scan log |
| `-interactive`, `-i` | disabled | Configure the scan with an interactive wizard |
| `-yes`, `-y` | disabled | Skip the wizard's final confirmation |
| `-quiet`, `-q` | disabled | Hide banner and progress messages |
| `-verbose`, `-v` | disabled | Include HTTP request, response, duration, and error debug logs |
| `-tools` | `default` | Comma-separated Framework v1 tools to run, `default`, or `all` |
| `-version` | disabled | Print the installed build version |
| `-list-tools` | disabled | List all Framework v1 scanner tools |

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
- Output directory
- Scanner tools to run

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
| `NVD_API_KEY` | No | NVD API key used by the CVE enrichment tool |

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

Set a custom User-Agent and output directory:

```bash
frameseven \
  -url https://target.example \
  -ua "authorized-security-test/v1" \
  -out audit-results
```

Enable request-level debug logs:

```bash
frameseven \
  -url https://target.example \
  --verbose
```

List the tools included in Framework v1:

```bash
frameseven --list-tools
```

Run only selected scanner tools:

```bash
frameseven \
  -url https://target.example \
  -tools sqli,misconfig
```

When a selected tool needs the discovered attack surface (`sqli`, `access`,
`ssrf`, `lfi`, `cve`, or `crawler`), CLI v1 includes `recon` automatically.

`default` runs the core web scanner tools. `all` also includes official opt-in
enumeration and integration tools: `crawler`, `content`, `subdomain`,
`ports`, `nmap`, `sqlmap`, and `bannergrab`.

Print the installed version:

```bash
frameseven --version
```

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | The scan completed without recorded tool request errors |
| `1` | A tool recorded a network error, or an output file could not be written |
| `2` | CLI configuration or flag validation failed |

Exit code `0` does not mean the target has no findings. Findings are reported
independently from command success.

## Network Behavior

- TLS certificate verification is disabled so the scanner can inspect targets
  with invalid certificates. Use the scanner only on authorized networks.
- Cross-origin redirects are blocked.
- Network failures are attached to the tool that was running.
- Findings are sorted from highest to lowest severity.

## Progress and Logs

CLI v1 prints the start and completion of every scanner tool to standard
error. Each completion message includes elapsed time, findings, and recorded
errors.

The same messages are written to `scan.log` in the output directory.
`--verbose` adds request-level HTTP details intended for debugging. These logs
can contain target URLs and probe payloads, so handle them as security test
data.

`--quiet` hides log messages from the terminal. The complete execution history,
including warnings and errors, remains available in `scan.log`.
