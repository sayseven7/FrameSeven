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

type listToolsInput struct{}

type toolInfo struct {
	Name             string `json:"name" jsonschema:"scanner tool name"`
	Description      string `json:"description" jsonschema:"short scanner tool description"`
	EnabledByDefault bool   `json:"enabled_by_default" jsonschema:"whether this tool runs in the default scan profile"`
}

type listToolsOutput struct {
	Version string     `json:"version" jsonschema:"framework version"`
	Tools   []toolInfo `json:"tools" jsonschema:"available Framework v1 scanner tools"`
}

type normalizeToolsInput struct {
	Tools []string `json:"tools" jsonschema:"tool names to validate; empty means the default tool set"`
}

type normalizeToolsOutput struct {
	Version           string   `json:"version" jsonschema:"framework version"`
	SelectedTools     []string `json:"selected_tools" jsonschema:"normalized tool names in execution order"`
	DefaultProfile    bool     `json:"default_profile" jsonschema:"whether the input resolved to the default scan profile"`
	SelectionSummary  string   `json:"selection_summary" jsonschema:"human-readable tool selection summary"`
	AvailableTools    []string `json:"available_tools" jsonschema:"all available Framework v1 tool names"`
	ActiveScanStarted bool     `json:"active_scan_started" jsonschema:"always false for this introductory MCP tool"`
}

type scanToolInput struct {
	Target             string   `json:"target" jsonschema:"authorized HTTP or HTTPS target URL"`
	TimeoutSeconds     int      `json:"timeout_seconds" jsonschema:"per-request timeout in seconds; uses the project default when empty"`
	RateRequests       int      `json:"rate_requests" jsonschema:"requests sent by the rate-limit tool; uses the project default when empty"`
	UserAgent          string   `json:"user_agent" jsonschema:"User-Agent header; uses the project default when empty"`
	NVDAPIKey          string   `json:"nvd_api_key" jsonschema:"optional NVD API key for CVE lookups"`
	ActiveScanAccepted bool     `json:"active_scan_accepted" jsonschema:"must be true to confirm this tool may send active security probes to the target"`
	ExtraTools         []string `json:"extra_tools" jsonschema:"optional additional Framework v1 tools to run with this tool"`
}

type scanToolOutput struct {
	Version       string             `json:"version" jsonschema:"framework version"`
	Target        string             `json:"target" jsonschema:"scanned target"`
	RequestedTool string             `json:"requested_tool" jsonschema:"MCP tool requested by the caller"`
	SelectedTools []string           `json:"selected_tools" jsonschema:"normalized scanner tools that were executed"`
	Duration      string             `json:"duration" jsonschema:"scan duration"`
	FindingsCount int                `json:"findings_count" jsonschema:"number of findings returned"`
	ErrorsCount   int                `json:"errors_count" jsonschema:"number of tool errors recorded"`
	Findings      []findingSummary   `json:"findings" jsonschema:"summarized findings"`
	Errors        []scanErrorSummary `json:"errors" jsonschema:"tool errors recorded during the scan"`
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

// V1ListTools returns the Framework v1 tool catalog.
func V1ListTools(ctx context.Context, req *mcpsdk.CallToolRequest, input listToolsInput) (*mcpsdk.CallToolResult, listToolsOutput, error) {
	var tools []toolInfo
	for _, tool := range scanner.Tools {
		tools = append(tools, toolInfo{
			Name:             tool.Name,
			Description:      tool.Description,
			EnabledByDefault: tool.EnabledByDefault,
		})
	}

	return nil, listToolsOutput{
		Version: "v1",
		Tools:   tools,
	}, nil
}

// V1NormalizeTools validates a tool selection without running any scanner tool.
func V1NormalizeTools(ctx context.Context, req *mcpsdk.CallToolRequest, input normalizeToolsInput) (*mcpsdk.CallToolResult, normalizeToolsOutput, error) {
	selected, err := scanner.NormalizeTools(input.Tools)
	if err != nil {
		return nil, normalizeToolsOutput{}, err
	}

	return nil, normalizeToolsOutput{
		Version:           "v1",
		SelectedTools:     selected,
		DefaultProfile:    len(input.Tools) == 0,
		SelectionSummary:  strings.Join(selected, ", "),
		AvailableTools:    scanner.ToolNames(),
		ActiveScanStarted: false,
	}, nil
}

// V1ScanTool returns an MCP handler for one Framework v1 scanner tool.
func V1ScanTool(toolName string) func(context.Context, *mcpsdk.CallToolRequest, scanToolInput) (*mcpsdk.CallToolResult, scanToolOutput, error) {
	return func(ctx context.Context, req *mcpsdk.CallToolRequest, input scanToolInput) (*mcpsdk.CallToolResult, scanToolOutput, error) {
		if !input.ActiveScanAccepted {
			return nil, scanToolOutput{}, errors.New("active_scan_accepted must be true before running scanner tools")
		}

		selected, err := scanner.NormalizeTools(append([]string{toolName}, input.ExtraTools...))
		if err != nil {
			return nil, scanToolOutput{}, err
		}

		cfg := buildScanConfig(input.Target, selected, input.TimeoutSeconds, input.RateRequests, input.UserAgent, input.NVDAPIKey)
		if err := cfg.Validate(); err != nil {
			return nil, scanToolOutput{}, err
		}

		rep := scanner.Scan(&cfg)

		return nil, buildScanToolOutput(toolName, selected, rep), nil
	}
}

func buildScanToolOutput(toolName string, selected []string, rep report.Report) scanToolOutput {
	return scanToolOutput{
		Version:       rep.SchemaVersion,
		Target:        rep.Target,
		RequestedTool: toolName,
		SelectedTools: selected,
		Duration:      rep.Duration,
		FindingsCount: len(rep.Findings),
		ErrorsCount:   len(rep.Errors),
		Findings:      summarizeFindings(rep.Findings),
		Errors:        summarizeErrors(rep.Errors),
	}
}

func buildScanConfig(target string, selected []string, timeoutSeconds, rateRequests int, userAgent, nvdAPIKey string) config.Config {
	cfg := config.New(target)
	cfg.SelectedTools = selected
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
