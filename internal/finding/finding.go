package finding

// Severity is the impact ranking of a finding.
type Severity string

const (
	Info     Severity = "INFO"
	Low      Severity = "LOW"
	Medium   Severity = "MEDIUM"
	High     Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

// Rank returns a numeric weight for a severity so findings can be sorted from
// most to least important.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// Evidence is the proof attached to a finding: the raw request and response
// that triggered it, plus any concrete value the tool managed to extract
// (for example a database version or a leaked credential).
type Evidence struct {
	Request   string `json:"request,omitempty"`
	Response  string `json:"response,omitempty"`
	Extracted string `json:"extracted,omitempty"`
}

// Finding is a single issue reported by a tool.
type Finding struct {
	Title       string   `json:"title"`
	Module      string   `json:"module"`
	Severity    Severity `json:"severity"`
	OWASP       string   `json:"owasp,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
	Description string   `json:"description"`
	Evidence    Evidence `json:"evidence,omitempty"`
	NextSteps   []string `json:"next_steps,omitempty"`
}

// SortBySeverity orders findings from most to least severe in place. Findings
// with equal severity keep a stable order by tool then title.
func SortBySeverity(findings []Finding) {
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && less(findings[j], findings[j-1]); j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
}

func less(a, b Finding) bool {
	if a.Severity.Rank() != b.Severity.Rank() {
		return a.Severity.Rank() > b.Severity.Rank()
	}

	if a.Module != b.Module {
		return a.Module < b.Module
	}

	return a.Title < b.Title
}
