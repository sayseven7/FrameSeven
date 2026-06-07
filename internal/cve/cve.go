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

const resultsPerProduct = 5

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
func Run(cfg *config.Config, client *http.Client, surface recon.Surface) []finding.Finding {
	var findings []finding.Finding
	seen := map[string]bool{}

	for _, tech := range surface.Technologies {
		keyword := versionKeyword(tech)
		if keyword == "" {
			continue
		}

		data, ok := lookup(cfg, client, keyword)
		if !ok {
			continue
		}

		for _, f := range parseNVD(data, keyword) {
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

func lookup(cfg *config.Config, client *http.Client, keyword string) ([]byte, bool) {
	q := url.Values{}
	q.Set("keywordSearch", keyword)
	q.Set("resultsPerPage", strconv.Itoa(resultsPerProduct))

	req, err := http.NewRequest(http.MethodGet, nvdEndpoint+"?"+q.Encode(), nil)
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

// parseNVD turns an NVD API response into findings. It is the pure, testable
// core of the module.
func parseNVD(data []byte, keyword string) []finding.Finding {
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
				Extracted: "matched component: " + keyword + " | " + v.CVE.ID,
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
