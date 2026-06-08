package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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
	ToolTimeoutSeconds int      `json:"tool_timeout_seconds" jsonschema:"maximum runtime for each scanner tool in seconds; uses the project default when empty"`
	Concurrency        int      `json:"concurrency" jsonschema:"scanner tools to run in parallel after recon; uses the project default when empty"`
	RateRequests       int      `json:"rate_requests" jsonschema:"requests sent by the rate-limit tool; uses the project default when empty"`
	UserAgent          string   `json:"user_agent" jsonschema:"User-Agent header; uses the project default when empty"`
	NVDAPIKey          string   `json:"nvd_api_key" jsonschema:"optional NVD API key for CVE lookups"`
	ActiveScanAccepted bool     `json:"active_scan_accepted" jsonschema:"must be true to confirm this tool may send active security probes to the target"`
	ExtraTools         []string `json:"extra_tools" jsonschema:"optional additional Framework v1 tools to run with this tool"`
	CustomPayloads     []string `json:"custom_payloads" jsonschema:"optional caller-supplied probes used by tools that support dynamic payloads"`
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

type reportToolInput struct {
	Target             string   `json:"target" jsonschema:"authorized HTTP or HTTPS target URL"`
	Tools              []string `json:"tools" jsonschema:"scanner tools to run; empty runs the default scan profile"`
	TimeoutSeconds     int      `json:"timeout_seconds" jsonschema:"per-request timeout in seconds; uses the project default when empty"`
	ToolTimeoutSeconds int      `json:"tool_timeout_seconds" jsonschema:"maximum runtime for each scanner tool in seconds; uses the project default when empty"`
	Concurrency        int      `json:"concurrency" jsonschema:"scanner tools to run in parallel after recon; uses the project default when empty"`
	RateRequests       int      `json:"rate_requests" jsonschema:"requests sent by the rate-limit tool; uses the project default when empty"`
	UserAgent          string   `json:"user_agent" jsonschema:"User-Agent header; uses the project default when empty"`
	NVDAPIKey          string   `json:"nvd_api_key" jsonschema:"optional NVD API key for CVE lookups"`
	ActiveScanAccepted bool     `json:"active_scan_accepted" jsonschema:"must be true to confirm this tool may send active security probes to the target"`
	CustomPayloads     []string `json:"custom_payloads" jsonschema:"optional caller-supplied probes used by tools that support dynamic payloads"`
	Format             string   `json:"format" jsonschema:"report format: text, markdown, html, pdf, both, or all; defaults to text"`
}

type reportToolOutput struct {
	Version        string   `json:"version" jsonschema:"framework version"`
	Target         string   `json:"target" jsonschema:"scanned target"`
	SelectedTools  []string `json:"selected_tools" jsonschema:"normalized scanner tools that were executed"`
	Duration       string   `json:"duration" jsonschema:"scan duration"`
	Status         string   `json:"status" jsonschema:"complete when no tool errors were recorded, otherwise incomplete"`
	FindingsCount  int      `json:"findings_count" jsonschema:"number of findings in the report"`
	ErrorsCount    int      `json:"errors_count" jsonschema:"number of tool errors recorded"`
	Format         string   `json:"format" jsonschema:"report format that was rendered"`
	ReportText     string   `json:"report_text,omitempty" jsonschema:"report rendered in the CLI text format"`
	ReportMarkdown string   `json:"report_markdown,omitempty" jsonschema:"report rendered in Markdown"`
	ReportHTML     string   `json:"report_html,omitempty" jsonschema:"self-contained HTML report"`
	ReportPDF      string   `json:"report_pdf_base64,omitempty" jsonschema:"base64-encoded PDF report bytes"`
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

		cfg := buildScanConfig(input.Target, selected, input.TimeoutSeconds, input.ToolTimeoutSeconds, input.Concurrency, input.RateRequests, input.UserAgent, input.NVDAPIKey)
		cfg.CustomPayloads = input.CustomPayloads

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

// V1Report runs a scan and renders the result in the same format the CLI
// produces, so MCP agents can assemble a report identical to the CLI's.
func V1Report(ctx context.Context, req *mcpsdk.CallToolRequest, input reportToolInput) (*mcpsdk.CallToolResult, reportToolOutput, error) {
	if !input.ActiveScanAccepted {
		return nil, reportToolOutput{}, errors.New("active_scan_accepted must be true before running scanner tools")
	}

	format, err := normalizeReportFormat(input.Format)
	if err != nil {
		return nil, reportToolOutput{}, err
	}

	selected, err := scanner.NormalizeTools(input.Tools)
	if err != nil {
		return nil, reportToolOutput{}, err
	}

	cfg := buildScanConfig(input.Target, selected, input.TimeoutSeconds, input.ToolTimeoutSeconds, input.Concurrency, input.RateRequests, input.UserAgent, input.NVDAPIKey)
	cfg.CustomPayloads = input.CustomPayloads

	if err := cfg.Validate(); err != nil {
		return nil, reportToolOutput{}, err
	}

	rep := scanner.Scan(&cfg)

	out, err := buildReportToolOutput(selected, format, rep)
	if err != nil {
		return nil, reportToolOutput{}, err
	}

	return nil, out, nil
}

func buildReportToolOutput(selected []string, format string, rep report.Report) (reportToolOutput, error) {
	out := reportToolOutput{
		Version:       rep.SchemaVersion,
		Target:        rep.Target,
		SelectedTools: selected,
		Duration:      rep.Duration,
		Status:        reportStatus(rep),
		FindingsCount: len(rep.Findings),
		ErrorsCount:   len(rep.Errors),
		Format:        format,
	}

	if format == reportFormatText || format == reportFormatBoth {
		out.ReportText = report.RenderText(rep)
	}

	if format == reportFormatMarkdown || format == reportFormatBoth || format == reportFormatAll {
		markdown, err := report.RenderMarkdown(rep)
		if err != nil {
			return reportToolOutput{}, err
		}

		out.ReportMarkdown = markdown
	}

	if format == reportFormatAll {
		out.ReportText = report.RenderText(rep)
	}

	if format == reportFormatHTML || format == reportFormatAll {
		html, err := report.RenderHTML(rep)
		if err != nil {
			return reportToolOutput{}, err
		}

		out.ReportHTML = html
	}

	if format == reportFormatPDF || format == reportFormatAll {
		pdf, err := report.RenderPDF(rep)
		if err != nil {
			return reportToolOutput{}, err
		}

		out.ReportPDF = base64.StdEncoding.EncodeToString(pdf)
	}

	return out, nil
}

const (
	reportFormatText     = "text"
	reportFormatMarkdown = "markdown"
	reportFormatHTML     = "html"
	reportFormatPDF      = "pdf"
	reportFormatBoth     = "both"
	reportFormatAll      = "all"
)

func normalizeReportFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", reportFormatText:
		return reportFormatText, nil
	case reportFormatMarkdown, "md":
		return reportFormatMarkdown, nil
	case reportFormatHTML:
		return reportFormatHTML, nil
	case reportFormatPDF:
		return reportFormatPDF, nil
	case reportFormatBoth, "all":
		if strings.EqualFold(strings.TrimSpace(format), "all") {
			return reportFormatAll, nil
		}

		return reportFormatBoth, nil
	default:
		return "", fmt.Errorf("unknown report format %q: use text, markdown, html, pdf, both, or all", format)
	}
}

func reportStatus(rep report.Report) string {
	if len(rep.Errors) > 0 {
		return "incomplete"
	}

	return "complete"
}

func buildScanConfig(target string, selected []string, timeoutSeconds, toolTimeoutSeconds, concurrency, rateRequests int, userAgent, nvdAPIKey string) config.Config {
	cfg := config.New(target)
	cfg.SelectedTools = selected
	cfg.Logger = log.New(io.Discard, "", 0)

	if timeoutSeconds > 0 {
		cfg.Timeout = time.Duration(timeoutSeconds) * time.Second
	}

	if toolTimeoutSeconds > 0 {
		cfg.ToolTimeout = time.Duration(toolTimeoutSeconds) * time.Second
	}

	if concurrency > 0 {
		cfg.ToolConcurrency = concurrency
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
