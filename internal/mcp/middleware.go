package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func createLoggingMiddleware() mcpsdk.Middleware {
	return func(next mcpsdk.MethodHandler) mcpsdk.MethodHandler {
		return func(ctx context.Context, method string, req mcpsdk.Request) (mcpsdk.Result, error) {
			started := time.Now()
			sessionID := req.GetSession().ID()

			identity, args := describeRequest(req.GetParams())

			log.Printf("MCP request session=%s method=%s%s%s", sessionID, method, identity, args)

			result, err := next(ctx, method, req)
			duration := time.Since(started).Round(time.Millisecond)

			if err != nil {
				log.Printf("MCP response session=%s method=%s%s status=error duration=%s error=%v", sessionID, method, identity, duration, err)
				return result, err
			}

			log.Printf("MCP response session=%s method=%s%s status=ok duration=%s%s", sessionID, method, identity, duration, describeResult(result))

			return result, nil
		}
	}
}

// describeRequest returns a short identity (the tool name, resource URI, or
// prompt name) and the relevant call arguments for one MCP request, so the log
// shows what was actually invoked instead of a bare method name.
func describeRequest(params mcpsdk.Params) (string, string) {
	switch p := params.(type) {
	case *mcpsdk.CallToolParamsRaw:
		return " tool=" + p.Name, describeToolArguments(p.Arguments)

	case *mcpsdk.ReadResourceParams:
		return " uri=" + p.URI, ""

	case *mcpsdk.GetPromptParams:
		return " prompt=" + p.Name, ""

	default:
		return "", ""
	}
}

// loggedToolArguments holds the call arguments worth surfacing in the logs.
type loggedToolArguments struct {
	Target             string   `json:"target"`
	Tools              []string `json:"tools"`
	ExtraTools         []string `json:"extra_tools"`
	Format             string   `json:"format"`
	ActiveScanAccepted bool     `json:"active_scan_accepted"`
	CustomPayloads     []string `json:"custom_payloads"`
}

// describeToolArguments extracts the key scanner arguments from the raw JSON
// arguments of a tools/call request.
func describeToolArguments(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var args loggedToolArguments
	if err := json.Unmarshal(raw, &args); err != nil {
		return ""
	}

	var parts []string

	if args.Target != "" {
		parts = append(parts, "target="+args.Target)
	}

	if len(args.Tools) > 0 {
		parts = append(parts, "tools=["+strings.Join(args.Tools, " ")+"]")
	}

	if len(args.ExtraTools) > 0 {
		parts = append(parts, "extra_tools=["+strings.Join(args.ExtraTools, " ")+"]")
	}

	if args.Format != "" {
		parts = append(parts, "format="+args.Format)
	}

	parts = append(parts, fmt.Sprintf("active_scan_accepted=%t", args.ActiveScanAccepted))

	if len(args.CustomPayloads) > 0 {
		parts = append(parts, fmt.Sprintf("custom_payloads=%d", len(args.CustomPayloads)))
	}

	return " " + strings.Join(parts, " ")
}

// loggedToolResult holds the scanner result fields worth surfacing in the logs.
type loggedToolResult struct {
	FindingsCount *int     `json:"findings_count"`
	ErrorsCount   *int     `json:"errors_count"`
	Status        string   `json:"status"`
	SelectedTools []string `json:"selected_tools"`
}

// describeResult summarizes an MCP result so the response log line carries the
// outcome (finding counts, list sizes) instead of only the duration.
func describeResult(result mcpsdk.Result) string {
	switch r := result.(type) {
	case *mcpsdk.CallToolResult:
		return describeToolResult(r)

	case *mcpsdk.ListToolsResult:
		return fmt.Sprintf(" tools=%d", len(r.Tools))

	case *mcpsdk.ListResourcesResult:
		return fmt.Sprintf(" resources=%d", len(r.Resources))

	case *mcpsdk.ReadResourceResult:
		return fmt.Sprintf(" contents=%d", len(r.Contents))

	default:
		return ""
	}
}

func describeToolResult(result *mcpsdk.CallToolResult) string {
	var parts []string

	if result.IsError {
		parts = append(parts, "tool_error=true")
	}

	summary := decodeToolResult(result.StructuredContent)

	if summary.SelectedTools != nil {
		parts = append(parts, "selected=["+strings.Join(summary.SelectedTools, " ")+"]")
	}

	if summary.FindingsCount != nil {
		parts = append(parts, fmt.Sprintf("findings=%d", *summary.FindingsCount))
	}

	if summary.ErrorsCount != nil {
		parts = append(parts, fmt.Sprintf("errors=%d", *summary.ErrorsCount))
	}

	if summary.Status != "" {
		parts = append(parts, "scan_status="+summary.Status)
	}

	if len(parts) == 0 {
		return ""
	}

	return " " + strings.Join(parts, " ")
}

// decodeToolResult re-marshals the typed structured content of a tool result so
// the logging layer can read the common scanner fields without importing every
// output type.
func decodeToolResult(structured any) loggedToolResult {
	var summary loggedToolResult

	if structured == nil {
		return summary
	}

	data, err := json.Marshal(structured)
	if err != nil {
		return summary
	}

	_ = json.Unmarshal(data, &summary)

	return summary
}
