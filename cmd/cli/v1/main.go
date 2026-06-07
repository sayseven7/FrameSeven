package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

const banner = "frameseven CLI v1 - offensive web scanner"

var buildVersion = "development"

var modules = []struct {
	Name        string
	Description string
}{
	{"recon", "DNS, technology, endpoint, parameter, and sensitive-file discovery"},
	{"sqli", "SQL injection detection and data extraction"},
	{"access", "Unauthenticated endpoint and IDOR checks"},
	{"ssrf", "Internal service and cloud metadata SSRF checks"},
	{"lfi", "Local file inclusion and path traversal checks"},
	{"misconfig", "Security header, HTTP method, CORS, and TLS checks"},
	{"ratelimit", "Request burst and rate-limit behavior checks"},
	{"cve", "NVD CVE lookup for detected product versions"},
}

type scanFunc func(*config.Config) report.Report

type options struct {
	target      string
	timeout     time.Duration
	rate        int
	userAgent   string
	output      string
	interactive bool
	yes         bool
	quiet       bool
	version     bool
	listModules bool
}

func main() {
	terminal := isTerminal(os.Stdin)
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, terminal, scanner.Scan)

	os.Exit(code)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, terminal bool, scan scanFunc) int {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}

	if err != nil {
		return 2
	}

	if opts.version {
		fmt.Fprintf(stdout, "frameseven %s (CLI v1)\n", buildVersion)
		return 0
	}

	if opts.listModules {
		writeModules(stdout)
		return 0
	}

	useWizard := opts.interactive || (opts.target == "" && terminal)
	if useWizard {
		if !terminal {
			fmt.Fprintln(stderr, "error: interactive mode requires a terminal")
			return 2
		}

		var confirmed bool
		opts, confirmed = runWizard(stdin, stdout, opts)
		if !confirmed {
			fmt.Fprintln(stderr, "scan cancelled")
			return 0
		}
	}

	cfg := config.New(opts.target)
	cfg.Timeout = opts.timeout
	cfg.RateRequests = opts.rate
	cfg.UserAgent = opts.userAgent
	cfg.NVDAPIKey = os.Getenv("NVD_API_KEY")

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	if !opts.quiet {
		fmt.Fprintf(stderr, "%s\nscanning %s ...\n\n", banner, cfg.Target)
	}

	rep := scan(&cfg)

	report.WriteText(stdout, rep)

	if opts.output != "" {
		if err := writeJSONFile(opts.output, rep); err != nil {
			fmt.Fprintf(stderr, "error writing report: %v\n", err)
			return 1
		}

		if !opts.quiet {
			fmt.Fprintf(stderr, "\nJSON report written to %s\n", opts.output)
		}
	}

	if len(rep.Errors) > 0 {
		return 1
	}

	return 0
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	opts := options{}
	flags := flag.NewFlagSet("frameseven", flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.StringVar(&opts.target, "url", "", "target URL to scan")
	flags.DurationVar(&opts.timeout, "timeout", config.DefaultTimeout, "per-request timeout")
	flags.IntVar(&opts.rate, "rate", config.DefaultRateRequests, "requests for the rate-limit test")
	flags.StringVar(&opts.userAgent, "ua", config.DefaultUserAgent, "User-Agent header")
	flags.StringVar(&opts.output, "o", "", "write the JSON report to this file")
	flags.BoolVar(&opts.interactive, "interactive", false, "configure the scan interactively")
	flags.BoolVar(&opts.interactive, "i", false, "configure the scan interactively")
	flags.BoolVar(&opts.yes, "yes", false, "accept the interactive scan confirmation")
	flags.BoolVar(&opts.yes, "y", false, "accept the interactive scan confirmation")
	flags.BoolVar(&opts.quiet, "quiet", false, "hide progress messages")
	flags.BoolVar(&opts.quiet, "q", false, "hide progress messages")
	flags.BoolVar(&opts.version, "version", false, "show the installed version")
	flags.BoolVar(&opts.listModules, "list-modules", false, "list scanner modules")

	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: frameseven -url https://target.example [flags]")
		fmt.Fprintln(stderr, "       frameseven --interactive")
		fmt.Fprintln(stderr)
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return options{}, err
	}

	if flags.NArg() > 0 {
		err := fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
		fmt.Fprintf(stderr, "error: %v\n", err)

		return options{}, err
	}

	return opts, nil
}

func runWizard(input io.Reader, output io.Writer, opts options) (options, bool) {
	reader := bufio.NewReader(input)

	fmt.Fprintln(output, banner)
	fmt.Fprintln(output, "Interactive scan setup")
	fmt.Fprintln(output)

	opts.target = prompt(reader, output, "Target URL", opts.target)
	opts.timeout = promptDuration(reader, output, "Per-request timeout", opts.timeout)
	opts.rate = promptInt(reader, output, "Rate-limit request count", opts.rate)
	opts.userAgent = prompt(reader, output, "User-Agent", opts.userAgent)
	opts.output = prompt(reader, output, "JSON report path (optional)", opts.output)

	fmt.Fprintln(output)
	fmt.Fprintln(output, "Scan configuration")
	fmt.Fprintf(output, "  Target:     %s\n", opts.target)
	fmt.Fprintf(output, "  Timeout:    %s\n", opts.timeout)
	fmt.Fprintf(output, "  Rate count: %d\n", opts.rate)
	fmt.Fprintf(output, "  User-Agent: %s\n", opts.userAgent)

	if opts.output == "" {
		fmt.Fprintln(output, "  JSON:       disabled")
	} else {
		fmt.Fprintf(output, "  JSON:       %s\n", opts.output)
	}

	if opts.yes {
		return opts, true
	}

	fmt.Fprintln(output)
	fmt.Fprintln(output, "This scan sends active security probes and may affect target state.")

	answer := prompt(reader, output, "Continue? [y/N]", "")

	return opts, strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
}

func prompt(reader *bufio.Reader, output io.Writer, label, defaultValue string) string {
	if defaultValue == "" {
		fmt.Fprintf(output, "%s: ", label)
	} else {
		fmt.Fprintf(output, "%s [%s]: ", label, defaultValue)
	}

	value, err := reader.ReadString('\n')
	if err != nil && len(value) == 0 {
		return defaultValue
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}

	return value
}

func promptDuration(reader *bufio.Reader, output io.Writer, label string, defaultValue time.Duration) time.Duration {
	for {
		value := prompt(reader, output, label, defaultValue.String())
		duration, err := time.ParseDuration(value)
		if err == nil && duration > 0 {
			return duration
		}

		fmt.Fprintln(output, "Enter a positive duration such as 10s or 1m.")
	}
}

func promptInt(reader *bufio.Reader, output io.Writer, label string, defaultValue int) int {
	for {
		value := prompt(reader, output, label, strconv.Itoa(defaultValue))
		number, err := strconv.Atoi(value)
		if err == nil && number > 0 {
			return number
		}

		fmt.Fprintln(output, "Enter a positive whole number.")
	}
}

func writeModules(output io.Writer) {
	fmt.Fprintln(output, "Framework modules v1")

	for _, module := range modules {
		fmt.Fprintf(output, "  %-10s %s\n", module.Name, module.Description)
	}
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

func writeJSONFile(path string, rep report.Report) error {
	file, err := os.Create(path) // #nosec G304 - path is provided by the operator
	if err != nil {
		return err
	}
	defer file.Close()

	return report.WriteJSON(file, rep)
}
