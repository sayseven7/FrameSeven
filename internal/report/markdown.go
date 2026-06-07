package report

import (
	"fmt"
	"io"
	"strings"
)

// WriteMarkdown renders a portable, human-readable report.
func WriteMarkdown(w io.Writer, rep Report) error {
	fmt.Fprintln(w, "# frameseven Scan Report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- **Target:** `%s`\n", rep.Target)
	fmt.Fprintf(w, "- **Started:** `%s`\n", rep.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "- **Duration:** `%s`\n", rep.Duration)
	fmt.Fprintf(w, "- **Status:** `%s`\n", reportStatus(rep))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Findings: **%d**\n", len(rep.Findings))
	fmt.Fprintf(w, "- %s\n", strings.TrimSpace(countsBySeverity(rep.Findings)))
	fmt.Fprintf(w, "- Module errors: **%d**\n", len(rep.Errors))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Attack Surface")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Host: `%s`\n", rep.Surface.Host)
	fmt.Fprintf(w, "- Technologies: **%d**\n", len(rep.Surface.Technologies))
	fmt.Fprintf(w, "- Endpoints: **%d**\n", len(rep.Surface.Endpoints))
	fmt.Fprintf(w, "- Parameters: **%d**\n", len(rep.Surface.Params))
	fmt.Fprintf(w, "- Sensitive files: **%d**\n", len(rep.Surface.SensitiveFiles))
	fmt.Fprintln(w)

	if len(rep.Errors) > 0 {
		fmt.Fprintln(w, "## Scan Errors")
		fmt.Fprintln(w)

		for _, scanErr := range rep.Errors {
			fmt.Fprintf(w, "- **%s:** %s\n", scanErr.Module, scanErr.Message)
		}

		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "## Findings")
	fmt.Fprintln(w)

	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")

		return nil
	}

	for i, item := range rep.Findings {
		fmt.Fprintf(w, "### %d. [%s] %s\n\n", i+1, item.Severity, item.Title)
		fmt.Fprintf(w, "- **Module:** `%s`\n", item.Module)

		if item.CVSS > 0 {
			fmt.Fprintf(w, "- **CVSS:** `%.1f`\n", item.CVSS)
		}

		if item.CWE != "" {
			fmt.Fprintf(w, "- **CWE:** `%s`\n", item.CWE)
		}

		if item.OWASP != "" {
			fmt.Fprintf(w, "- **OWASP:** `%s`\n", item.OWASP)
		}

		fmt.Fprintln(w)
		fmt.Fprintln(w, item.Description)
		fmt.Fprintln(w)

		writeMarkdownEvidence(w, "Request", item.Evidence.Request)
		writeMarkdownEvidence(w, "Response", item.Evidence.Response)
		writeMarkdownEvidence(w, "Extracted Evidence", item.Evidence.Extracted)

		if len(item.NextSteps) > 0 {
			fmt.Fprintln(w, "#### Next Steps")
			fmt.Fprintln(w)

			for _, step := range item.NextSteps {
				fmt.Fprintf(w, "- %s\n", step)
			}

			fmt.Fprintln(w)
		}
	}

	return nil
}

func writeMarkdownEvidence(w io.Writer, title, value string) {
	if value == "" {
		return
	}

	fmt.Fprintf(w, "#### %s\n\n", title)
	fmt.Fprintln(w, "```text")
	fmt.Fprintln(w, value)
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)
}

func reportStatus(rep Report) string {
	if len(rep.Errors) > 0 {
		return "incomplete"
	}

	return "complete"
}
