// Package nmap checks whether Nmap is available for Framework v1 integrations.
package nmap

import (
	"os/exec"

	"github.com/sayseven7/frameseven/internal/finding"
)

// Run reports whether the Nmap binary is available. It does not execute Nmap.
func Run() []finding.Finding {
	path, err := exec.LookPath("nmap")
	if err != nil {
		return []finding.Finding{notFound("nmap")}
	}

	return []finding.Finding{found("nmap", path)}
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
			"Add explicit execution profiles before running external tools.",
			"Keep external tool output format versioned.",
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
