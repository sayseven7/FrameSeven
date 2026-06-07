// Package sqlmap checks whether sqlmap is available for Framework v1 integrations.
package sqlmap

import (
	"os/exec"

	"github.com/sayseven7/frameseven/internal/finding"
)

// Run reports whether the sqlmap binary is available. It does not execute sqlmap.
func Run() []finding.Finding {
	path, err := exec.LookPath("sqlmap")
	if err != nil {
		return []finding.Finding{notFound("sqlmap")}
	}

	return []finding.Finding{found("sqlmap", path)}
}

func found(name, path string) finding.Finding {
	return finding.Finding{
		Title:       name + " binary available",
		Module:      name,
		Severity:    finding.Info,
		Description: name + " was found on the operator machine. Framework v1 records availability but does not execute it yet.",
		Evidence: finding.Evidence{
			Extracted: "binary: " + path,
		},
		NextSteps: []string{
			"Require explicit target parameters before running external tools.",
			"Keep external tool execution profiles and output format versioned.",
		},
	}
}

func notFound(name string) finding.Finding {
	return finding.Finding{
		Title:       name + " binary not found",
		Module:      name,
		Severity:    finding.Info,
		Description: name + " is not installed or is not available in PATH.",
		Evidence: finding.Evidence{
			Extracted: "binary not found in PATH",
		},
		NextSteps: []string{
			"Install the external tool before enabling execution support.",
			"Keep this module selected only when external tooling is needed.",
		},
	}
}
