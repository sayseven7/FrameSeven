package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

const banner = "frameseven CLI v1 - offensive web scanner"

func main() {
	target := flag.String("url", "", "target URL to scan (required)")
	timeout := flag.Duration("timeout", config.DefaultTimeout, "per-request timeout")
	rate := flag.Int("rate", config.DefaultRateRequests, "number of requests for the rate-limit test")
	userAgent := flag.String("ua", config.DefaultUserAgent, "User-Agent header")
	output := flag.String("o", "", "write the JSON report to this file (optional)")

	flag.Parse()

	cfg := config.New(*target)
	cfg.Timeout = *timeout
	cfg.RateRequests = *rate
	cfg.UserAgent = *userAgent
	cfg.NVDAPIKey = os.Getenv("NVD_API_KEY")

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		flag.Usage()
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "%s\nscanning %s ...\n\n", banner, cfg.Target)

	rep := scanner.Scan(&cfg)

	report.WriteText(os.Stdout, rep)

	if *output != "" {
		if err := writeJSONFile(*output, rep); err != nil {
			fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "\nJSON report written to %s\n", *output)
	}

	if len(rep.Errors) > 0 {
		os.Exit(1)
	}
}

func writeJSONFile(path string, rep report.Report) error {
	file, err := os.Create(path) // #nosec G304 - path is provided by the operator
	if err != nil {
		return err
	}
	defer file.Close()

	return report.WriteJSON(file, rep)
}
