// Package subdomain resolves a small seed list of common subdomain names.
package subdomain

import (
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

var candidates = []string{
	"www",
	"api",
	"app",
	"admin",
	"administrator",
	"auth",
	"login",
	"sso",
	"oauth",
	"accounts",
	"account",
	"portal",
	"dashboard",
	"panel",
	"console",
	"cpanel",
	"webmail",
	"mail",
	"smtp",
	"imap",
	"pop",
	"mx",
	"email",
	"dev",
	"devel",
	"development",
	"test",
	"testing",
	"qa",
	"uat",
	"stage",
	"staging",
	"preprod",
	"preview",
	"beta",
	"alpha",
	"demo",
	"sandbox",
	"lab",
	"labs",
	"internal",
	"intranet",
	"vpn",
	"remote",
	"secure",
	"gateway",
	"proxy",
	"cdn",
	"static",
	"assets",
	"media",
	"images",
	"img",
	"files",
	"download",
	"downloads",
	"upload",
	"uploads",
	"docs",
	"doc",
	"help",
	"support",
	"status",
	"health",
	"monitor",
	"monitoring",
	"metrics",
	"grafana",
	"kibana",
	"prometheus",
	"logs",
	"log",
	"jenkins",
	"ci",
	"build",
	"git",
	"gitlab",
	"github",
	"repo",
	"repos",
	"svn",
	"jira",
	"confluence",
	"wiki",
	"crm",
	"erp",
	"shop",
	"store",
	"blog",
	"news",
	"cms",
	"wordpress",
	"wp",
	"api-dev",
	"api-test",
	"api-stage",
	"api-staging",
	"api-prod",
	"mobile",
	"m",
	"web",
	"www2",
	"old",
	"new",
	"backup",
	"backups",
	"db",
	"database",
	"mysql",
	"postgres",
	"redis",
	"elastic",
	"search",
	"queue",
	"worker",
	"node1",
	"node2",
	"server",
	"server1",
	"ns1",
	"ns2",
	"dns",
	"ftp",
	"ssh",
	"bastion",
	"jump",
	"payments",
	"billing",
	"invoice",
	"partners",
	"partner",
	"vendor",
}

var candidateLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)

// Run resolves common subdomain candidates and reports any that exist.
func Run(cfg *config.Config, _ *http.Client, _ *recon.Surface) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	root := rootDomain(base.Hostname())
	if root == "" {
		return nil
	}

	var found []string
	for _, candidate := range allCandidates(cfg) {
		host := candidate + "." + root
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			continue
		}

		found = append(found, host+" -> "+strings.Join(addrs, ", "))
	}

	if len(found) == 0 {
		return nil
	}

	return []finding.Finding{{
		Title:       "Common subdomains resolved",
		Module:      "subdomain",
		Severity:    finding.Info,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-200",
		Description: "Common subdomain candidates resolved through DNS.",
		Evidence: finding.Evidence{
			Extracted: strings.Join(found, "\n"),
		},
		NextSteps: []string{
			"Review resolved hosts for authorization and scope before testing them.",
			"Add wildcard DNS detection before expanding the subdomain wordlist.",
		},
	}}
}

func rootDomain(host string) string {
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}

	return strings.Join(parts[len(parts)-2:], ".")
}

func allCandidates(cfg *config.Config) []string {
	seen := map[string]bool{}
	var selected []string

	for _, candidate := range candidates {
		selected = appendCandidate(selected, seen, candidate)
	}

	for _, payload := range cfg.NormalizedCustomPayloads() {
		selected = appendCandidate(selected, seen, strings.Trim(payload, "."))
	}

	return selected
}

func appendCandidate(candidates []string, seen map[string]bool, candidate string) []string {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if candidate == "" || seen[candidate] || !candidateLabel.MatchString(candidate) {
		return candidates
	}

	seen[candidate] = true

	return append(candidates, candidate)
}
