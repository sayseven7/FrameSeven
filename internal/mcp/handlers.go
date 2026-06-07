package mcp

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

type listModulesInput struct{}

type moduleInfo struct {
	Name             string `json:"name" jsonschema:"scanner module name"`
	Description      string `json:"description" jsonschema:"short scanner module description"`
	EnabledByDefault bool   `json:"enabled_by_default" jsonschema:"whether this module runs in the default scan profile"`
}

type listModulesOutput struct {
	Version string       `json:"version" jsonschema:"framework version"`
	Modules []moduleInfo `json:"modules" jsonschema:"available Framework v1 scanner modules"`
}

type normalizeModulesInput struct {
	Modules []string `json:"modules" jsonschema:"module names to validate; empty means the default module set"`
}

type normalizeModulesOutput struct {
	Version           string   `json:"version" jsonschema:"framework version"`
	SelectedModules   []string `json:"selected_modules" jsonschema:"normalized module names in execution order"`
	DefaultProfile    bool     `json:"default_profile" jsonschema:"whether the input resolved to the default scan profile"`
	SelectionSummary  string   `json:"selection_summary" jsonschema:"human-readable module selection summary"`
	AvailableModules  []string `json:"available_modules" jsonschema:"all available Framework v1 module names"`
	ActiveScanStarted bool     `json:"active_scan_started" jsonschema:"always false for this introductory MCP tool"`
}

type scanModuleInput struct {
	Target             string   `json:"target" jsonschema:"authorized HTTP or HTTPS target URL"`
	TimeoutSeconds     int      `json:"timeout_seconds" jsonschema:"per-request timeout in seconds; uses the project default when empty"`
	RateRequests       int      `json:"rate_requests" jsonschema:"requests sent by the rate-limit module; uses the project default when empty"`
	UserAgent          string   `json:"user_agent" jsonschema:"User-Agent header; uses the project default when empty"`
	NVDAPIKey          string   `json:"nvd_api_key" jsonschema:"optional NVD API key for CVE lookups"`
	ActiveScanAccepted bool     `json:"active_scan_accepted" jsonschema:"must be true to confirm this tool may send active security probes to the target"`
	ExtraModules       []string `json:"extra_modules" jsonschema:"optional additional Framework v1 modules to run with this module"`
}

type scanModuleOutput struct {
	Version         string             `json:"version" jsonschema:"framework version"`
	Target          string             `json:"target" jsonschema:"scanned target"`
	RequestedModule string             `json:"requested_module" jsonschema:"MCP tool module requested by the caller"`
	SelectedModules []string           `json:"selected_modules" jsonschema:"normalized scanner modules that were executed"`
	Duration        string             `json:"duration" jsonschema:"scan duration"`
	FindingsCount   int                `json:"findings_count" jsonschema:"number of findings returned"`
	ErrorsCount     int                `json:"errors_count" jsonschema:"number of module errors recorded"`
	Findings        []findingSummary   `json:"findings" jsonschema:"summarized findings"`
	Errors          []scanErrorSummary `json:"errors" jsonschema:"module errors recorded during the scan"`
}

type findingSummary struct {
	Title       string   `json:"title" jsonschema:"finding title"`
	Module      string   `json:"module" jsonschema:"module that reported the finding"`
	Severity    string   `json:"severity" jsonschema:"finding severity"`
	OWASP       string   `json:"owasp,omitempty" jsonschema:"OWASP category when available"`
	CWE         string   `json:"cwe,omitempty" jsonschema:"CWE identifier when available"`
	CVSS        float64  `json:"cvss,omitempty" jsonschema:"CVSS score when available"`
	Description string   `json:"description" jsonschema:"finding description"`
	Evidence    string   `json:"evidence,omitempty" jsonschema:"short extracted evidence when available"`
	NextSteps   []string `json:"next_steps,omitempty" jsonschema:"recommended next steps"`
}

type scanErrorSummary struct {
	Module  string `json:"module" jsonschema:"module that recorded the error"`
	Message string `json:"message" jsonschema:"error message"`
}

// ListModules returns the Framework v1 module catalog.
func V1ListModules(ctx context.Context, req *mcpsdk.CallToolRequest, input listModulesInput) (*mcpsdk.CallToolResult, listModulesOutput, error) {
	var modules []moduleInfo
	for _, module := range scanner.Modules {
		modules = append(modules, moduleInfo{
			Name:             module.Name,
			Description:      module.Description,
			EnabledByDefault: module.EnabledByDefault,
		})
	}

	return nil, listModulesOutput{
		Version: "v1",
		Modules: modules,
	}, nil
}

// NormalizeModules validates a module selection without running any scanner module.
func V1NormalizeModules(ctx context.Context, req *mcpsdk.CallToolRequest, input normalizeModulesInput) (*mcpsdk.CallToolResult, normalizeModulesOutput, error) {
	selected, err := scanner.NormalizeModules(input.Modules)
	if err != nil {
		return nil, normalizeModulesOutput{}, err
	}

	return nil, normalizeModulesOutput{
		Version:           "v1",
		SelectedModules:   selected,
		DefaultProfile:    len(input.Modules) == 0,
		SelectionSummary:  strings.Join(selected, ", "),
		AvailableModules:  scanner.ModuleNames(),
		ActiveScanStarted: false,
	}, nil
}

// V1ScanModule returns an MCP handler for one Framework v1 scanner module.
func V1ScanModule(moduleName string) func(context.Context, *mcpsdk.CallToolRequest, scanModuleInput) (*mcpsdk.CallToolResult, scanModuleOutput, error) {
	return func(ctx context.Context, req *mcpsdk.CallToolRequest, input scanModuleInput) (*mcpsdk.CallToolResult, scanModuleOutput, error) {
		if !input.ActiveScanAccepted {
			return nil, scanModuleOutput{}, errors.New("active_scan_accepted must be true before running scanner modules")
		}

		selected, err := scanner.NormalizeModules(append([]string{moduleName}, input.ExtraModules...))
		if err != nil {
			return nil, scanModuleOutput{}, err
		}

		cfg := buildScanConfig(input.Target, selected, input.TimeoutSeconds, input.RateRequests, input.UserAgent, input.NVDAPIKey)
		if err := cfg.Validate(); err != nil {
			return nil, scanModuleOutput{}, err
		}

		rep := scanner.Scan(&cfg)

		return nil, buildScanModuleOutput(moduleName, selected, rep), nil
	}
}

func buildScanModuleOutput(moduleName string, selected []string, rep report.Report) scanModuleOutput {
	return scanModuleOutput{
		Version:         rep.SchemaVersion,
		Target:          rep.Target,
		RequestedModule: moduleName,
		SelectedModules: selected,
		Duration:        rep.Duration,
		FindingsCount:   len(rep.Findings),
		ErrorsCount:     len(rep.Errors),
		Findings:        summarizeFindings(rep.Findings),
		Errors:          summarizeErrors(rep.Errors),
	}
}

func buildScanConfig(target string, selected []string, timeoutSeconds, rateRequests int, userAgent, nvdAPIKey string) config.Config {
	cfg := config.New(target)
	cfg.SelectedModules = selected
	cfg.Logger = log.New(io.Discard, "", 0)

	if timeoutSeconds > 0 {
		cfg.Timeout = time.Duration(timeoutSeconds) * time.Second
	}

	if rateRequests > 0 {
		cfg.RateRequests = rateRequests
	}

	if strings.TrimSpace(userAgent) != "" {
		cfg.UserAgent = userAgent
	}

	cfg.NVDAPIKey = nvdAPIKey

	return cfg
}

func summarizeFindings(findings []finding.Finding) []findingSummary {
	var summaries []findingSummary
	for _, item := range findings {
		summaries = append(summaries, findingSummary{
			Title:       item.Title,
			Module:      item.Module,
			Severity:    string(item.Severity),
			OWASP:       item.OWASP,
			CWE:         item.CWE,
			CVSS:        item.CVSS,
			Description: item.Description,
			Evidence:    firstEvidence(item),
			NextSteps:   item.NextSteps,
		})
	}

	return summaries
}

func summarizeErrors(errors []report.ScanErrorV1) []scanErrorSummary {
	var summaries []scanErrorSummary
	for _, item := range errors {
		summaries = append(summaries, scanErrorSummary{
			Module:  item.Module,
			Message: item.Message,
		})
	}

	return summaries
}

func firstEvidence(item finding.Finding) string {
	if strings.TrimSpace(item.Evidence.Extracted) != "" {
		return trimEvidence(item.Evidence.Extracted)
	}

	if strings.TrimSpace(item.Evidence.Response) != "" {
		return trimEvidence(item.Evidence.Response)
	}

	return trimEvidence(item.Evidence.Request)
}

func trimEvidence(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 500 {
		return value[:500]
	}

	return value
}
