// Package main implements the frameseven CLI v1 entry point. It parses flags,
// runs an optional interactive wizard, and orchestrates a scan via scanner.Scan.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

const bannerTitle = "frameseven CLI v1 - offensive web scanner"
const defaultOutputDir = "reports"

const cliBanner = `
                 (` + "`" + `-').-> (` + "`" + `-')  _         _  (` + "`" + `-')
                 (OO )__  ( OO).-/  <-.    \-.(OO )
                ,--. ,'-'(,------.,--. )   _.'    \
                |  | |  | |  .---'|  (` + "`" + `-')(_...--''
                |  ` + "`" + `-'  |(|  '--. |  |OO )|  |_.'
                |  .-.  | |  .--'(|  '__ ||  .___.
                |  | |  | |  ` + "`" + `---.|     |'|  |
                ` + "`" + `--' ` + "`" + `--' ` + "`" + `------'` + "`" + `-----' ` + "`" + `--'
                            FrameSeven v1.0.0 Version
`

var buildVersion = "development"

type scanFunc func(*config.Config) report.Report

type options struct {
	target      string
	timeout     time.Duration
	rate        int
	userAgent   string
	outputDir   string
	interactive bool
	yes         bool
	quiet       bool
	verbose     bool
	version     bool
	listTools   bool
	tools       []string
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

	if opts.listTools {
		writeTools(stdout)
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
	cfg.SelectedTools = opts.tools

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	logFile, err := openLogFile(opts.outputDir)
	if err != nil {
		fmt.Fprintf(stderr, "error creating scan log: %v\n", err)
		return 1
	}
	defer logFile.Close()

	logOutput := io.Writer(logFile)
	if !opts.quiet {
		logOutput = io.MultiWriter(stderr, logFile)
	}

	cfg.Logger = log.New(logOutput, "", log.Ltime)
	cfg.Verbose = opts.verbose
	if !opts.quiet {
		writeBanner(stderr)
	}

	cfg.Logger.Printf("INFO  %s", bannerTitle)
	cfg.Logger.Printf("INFO  scan started for %s", cfg.Target)
	cfg.Logger.Printf("INFO  output directory: %s", opts.outputDir)
	cfg.Logger.Printf("INFO  selected tools: %s", strings.Join(cfg.SelectedTools, ", "))

	rep := scan(&cfg)

	report.WriteText(stdout, rep)

	files, err := report.WriteFiles(opts.outputDir, rep)
	if err != nil {
		cfg.Logger.Printf("ERROR could not write reports: %v", err)
		return 1
	}

	cfg.Logger.Printf("INFO  HTML report: %s", files.HTML)
	cfg.Logger.Printf("INFO  Markdown report: %s", files.Markdown)
	cfg.Logger.Printf("INFO  JSON report: %s", files.JSON)
	cfg.Logger.Printf("INFO  scan log: %s", filepath.Join(opts.outputDir, "scan.log"))

	if len(rep.Errors) > 0 {
		cfg.Logger.Printf("WARN  scan finished with %d recorded tool error(s)", len(rep.Errors))
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
	flags.StringVar(&opts.outputDir, "out", defaultOutputDir, "directory for reports and scan logs")
	flags.StringVar(&opts.outputDir, "o", defaultOutputDir, "directory for reports and scan logs")
	flags.BoolVar(&opts.interactive, "interactive", false, "configure the scan interactively")
	flags.BoolVar(&opts.interactive, "i", false, "configure the scan interactively")
	flags.BoolVar(&opts.yes, "yes", false, "accept the interactive scan confirmation")
	flags.BoolVar(&opts.yes, "y", false, "accept the interactive scan confirmation")
	flags.BoolVar(&opts.quiet, "quiet", false, "hide progress messages")
	flags.BoolVar(&opts.quiet, "q", false, "hide progress messages")
	flags.BoolVar(&opts.verbose, "verbose", false, "show HTTP request and response debug logs")
	flags.BoolVar(&opts.verbose, "v", false, "show HTTP request and response debug logs")
	flags.BoolVar(&opts.version, "version", false, "show the installed version")
	flags.BoolVar(&opts.listTools, "list-tools", false, "list scanner tools")

	var toolList string
	flags.StringVar(&toolList, "tools", "", "comma-separated scanner tools to run, default, or all")

	flags.Usage = func() {
		writeBanner(stderr)
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

	toolNames, err := parseToolList(toolList)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)

		return options{}, err
	}

	opts.tools = toolNames

	return opts, nil
}

func runWizard(input io.Reader, output io.Writer, opts options) (options, bool) {
	reader := bufio.NewReader(input)

	writeBanner(output)
	fmt.Fprintln(output, "Interactive scan setup")
	fmt.Fprintln(output)

	opts.target = prompt(reader, output, "Target URL", opts.target)
	opts.timeout = promptDuration(reader, output, "Per-request timeout", opts.timeout)
	opts.rate = promptInt(reader, output, "Rate-limit request count", opts.rate)
	opts.userAgent = prompt(reader, output, "User-Agent", opts.userAgent)
	opts.outputDir = prompt(reader, output, "Output directory", opts.outputDir)
	opts.tools = promptTools(reader, output, opts.tools)

	fmt.Fprintln(output)
	fmt.Fprintln(output, "Scan configuration")
	fmt.Fprintf(output, "  Target:     %s\n", opts.target)
	fmt.Fprintf(output, "  Timeout:    %s\n", opts.timeout)
	fmt.Fprintf(output, "  Rate count: %d\n", opts.rate)
	fmt.Fprintf(output, "  User-Agent: %s\n", opts.userAgent)
	fmt.Fprintf(output, "  Output:     %s\n", opts.outputDir)
	fmt.Fprintf(output, "  Tools:    %s\n", strings.Join(opts.tools, ", "))

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

func promptTools(reader *bufio.Reader, output io.Writer, current []string) []string {
	defaultValue := "default"
	if len(current) > 0 {
		defaultValue = strings.Join(current, ",")
	}

	fmt.Fprintln(output)
	fmt.Fprintln(output, "Available tools")
	for i, tool := range scanner.Tools {
		fmt.Fprintf(output, "  %d) %-10s %s\n", i+1, tool.Name, tool.Description)
	}

	for {
		value := prompt(reader, output, "Tools to run (numbers or names, comma-separated)", defaultValue)
		selected, err := parseToolList(value)
		if err == nil {
			return selected
		}

		fmt.Fprintf(output, "%v\n", err)
	}
}

func writeTools(output io.Writer) {
	fmt.Fprintln(output, "Framework tools v1")

	for _, tool := range scanner.Tools {
		fmt.Fprintf(output, "  %-10s %s\n", tool.Name, tool.Description)
	}
}

func writeBanner(output io.Writer) {
	fmt.Fprint(output, cliBanner)
}

func parseToolList(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "default") {
		return scanner.NormalizeTools(nil)
	}

	if strings.EqualFold(value, "all") {
		return scanner.NormalizeTools(scanner.ToolNames())
	}

	byName := map[string]string{}
	for i, tool := range scanner.Tools {
		byName[tool.Name] = tool.Name
		byName[strconv.Itoa(i+1)] = tool.Name
	}

	seen := map[string]bool{}
	var selected []string

	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	}) {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}

		name, ok := byName[part]
		if !ok {
			return nil, fmt.Errorf("unknown scanner tool %q", part)
		}

		if !seen[name] {
			seen[name] = true
			selected = append(selected, name)
		}
	}

	if len(selected) == 0 {
		return nil, errors.New("at least one scanner tool must be selected")
	}

	return scanner.NormalizeTools(selected)
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

func openLogFile(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, "scan.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // #nosec G304 - the operator selects the output directory
	if err != nil {
		return nil, err
	}

	return file, nil
}
