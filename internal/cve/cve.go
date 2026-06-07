// Package cve maps detected technology versions to known CVEs using the public
// NVD API 2.0. It is enrichment over the recon surface, not an active test.
package cve

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

const nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const cpeEndpoint = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

const resultsPerProduct = 5
const cpeResultsPerProduct = 20

type cpeResponse struct {
	Products []struct {
		CPE nvdCPE `json:"cpe"`
	} `json:"products"`
}

type nvdCPE struct {
	Deprecated bool             `json:"deprecated"`
	CPEName    string           `json:"cpeName"`
	Titles     []nvdDescription `json:"titles"`
}

// nvdResponse mirrors the subset of the NVD API 2.0 schema we consume.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      struct {
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []nvdWeakness `json:"weaknesses"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// Run looks up CVEs for every versioned technology in the surface.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	seen := map[string]bool{}

	for _, tech := range surface.Technologies {
		keyword := versionKeyword(tech)
		if keyword == "" {
			continue
		}

		cpeName, ok := resolveCPE(cfg, client, tech)
		if !ok {
			continue
		}

		data, ok := lookup(cfg, client, cpeName)
		if !ok {
			continue
		}

		for _, f := range parseNVD(data, keyword, cpeName) {
			if seen[f.Title] {
				continue
			}

			seen[f.Title] = true
			findings = append(findings, f)
		}
	}

	return findings
}

// versionKeyword returns the NVD keyword search string for a technology, or
// empty when there is no version to match against.
func versionKeyword(tech recon.Technology) string {
	if tech.Version == "" {
		return ""
	}

	return tech.Name + " " + tech.Version
}

func resolveCPE(cfg *config.Config, client *http.Client, tech recon.Technology) (string, bool) {
	q := url.Values{}
	q.Set("keywordSearch", versionKeyword(tech))
	q.Set("resultsPerPage", strconv.Itoa(cpeResultsPerProduct))

	body, ok := requestNVD(cfg, client, cpeEndpoint+"?"+q.Encode())
	if !ok {
		return "", false
	}

	return parseExactCPE(body, tech)
}

func lookup(cfg *config.Config, client *http.Client, cpeName string) ([]byte, bool) {
	q := url.Values{}
	q.Set("cpeName", cpeName)
	q.Set("resultsPerPage", strconv.Itoa(resultsPerProduct))

	return requestNVD(cfg, client, nvdEndpoint+"?"+q.Encode())
}

func requestNVD(cfg *config.Config, client *http.Client, endpoint string) ([]byte, bool) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	if cfg.NVDAPIKey != "" {
		req.Header.Set("apiKey", cfg.NVDAPIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, false
	}

	return body, true
}

func parseExactCPE(data []byte, tech recon.Technology) (string, bool) {
	var parsed cpeResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", false
	}

	var matches []string
	seen := map[string]bool{}

	for _, product := range parsed.Products {
		cpe := product.CPE
		if cpe.Deprecated || cpe.CPEName == "" || !cpeMatchesTechnology(cpe, tech) || seen[cpe.CPEName] {
			continue
		}

		seen[cpe.CPEName] = true
		matches = append(matches, cpe.CPEName)
	}

	if len(matches) != 1 {
		return "", false
	}

	return matches[0], true
}

func cpeMatchesTechnology(cpe nvdCPE, tech recon.Technology) bool {
	parts := strings.Split(cpe.CPEName, ":")
	if len(parts) < 6 || parts[5] != tech.Version {
		return false
	}

	name := normalizeProductName(tech.Name)
	if name == "" {
		return false
	}

	for _, title := range cpe.Titles {
		if title.Lang != "en" {
			continue
		}

		normalizedTitle := normalizeProductName(title.Value)
		if strings.Contains(" "+normalizedTitle+" ", " "+name+" ") {
			return true
		}
	}

	return false
}

func normalizeProductName(value string) string {
	value = strings.ToLower(value)

	return strings.Join(strings.FieldsFunc(value, func(r rune) bool {
		return r < 'a' || r > 'z'
	}), " ")
}

// parseNVD turns an NVD API response into findings. It is the pure, testable
// core of the module.
func parseNVD(data []byte, keyword, cpeName string) []finding.Finding {
	var parsed nvdResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}

	var findings []finding.Finding

	for _, v := range parsed.Vulnerabilities {
		score := baseScore(v.CVE.Metrics.V31, v.CVE.Metrics.V30, v.CVE.Metrics.V2)

		findings = append(findings, finding.Finding{
			Title:       v.CVE.ID + " affects " + keyword,
			Module:      "cve",
			Severity:    severityFromScore(score),
			OWASP:       "A06:2025 - Vulnerable and Outdated Components",
			CWE:         firstCWE(v.CVE.Weaknesses),
			CVSS:        score,
			Description: description(v.CVE.Descriptions),
			Evidence: finding.Evidence{
				Extracted: "matched component: " + keyword + "\nCPE: " + cpeName + "\nCVE: " + v.CVE.ID,
			},
			NextSteps: []string{
				"Upgrade " + keyword + " to a fixed release.",
				"Review the CVE advisory and apply vendor mitigations until patched.",
			},
		})
	}

	return findings
}

func baseScore(groups ...[]nvdMetric) float64 {
	for _, group := range groups {
		if len(group) > 0 {
			return group[0].CVSSData.BaseScore
		}
	}

	return 0
}

func severityFromScore(score float64) finding.Severity {
	switch {
	case score >= 9.0:
		return finding.Critical
	case score >= 7.0:
		return finding.High
	case score >= 4.0:
		return finding.Medium
	case score > 0:
		return finding.Low
	default:
		return finding.Info
	}
}

func firstCWE(weaknesses []nvdWeakness) string {
	for _, w := range weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				return d.Value
			}
		}
	}

	return ""
}

func description(descriptions []nvdDescription) string {
	for _, d := range descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}

	if len(descriptions) > 0 {
		return descriptions[0].Value
	}

	return ""
}
