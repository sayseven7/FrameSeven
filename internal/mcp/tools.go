package mcp

import (
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

var (
	destructiveHint = true
	readOnlyHint    = true
	idempotentHint  = true
)

// RegisterTools adds the FrameSeven MCP tools.
func RegisterTools(server *mcpsdk.Server) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_list_tools",
		Title:       "List Scanner Tools",
		Description: "List Framework v1 scanner tools and whether each tool runs by default.",
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint:   readOnlyHint,
			IdempotentHint: idempotentHint,
		},
	}, V1ListTools)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_normalize_tools",
		Title:       "Normalize Tool Selection",
		Description: "Validate and normalize a Framework v1 tool selection without starting a scan.",
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint:   readOnlyHint,
			IdempotentHint: idempotentHint,
		},
	}, V1NormalizeTools)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_report",
		Title:       "Run Scan and Render CLI Report",
		Description: "Run Framework v1 scanner tools and return the result rendered as text, Markdown, HTML, PDF, or all report formats. Pass auth_cookies and/or auth_headers (and optional seed_endpoints) to run the scan as an authenticated session.",
		Annotations: &mcpsdk.ToolAnnotations{
			DestructiveHint: &destructiveHint,
		},
	}, V1Report)

	for _, tool := range scanner.Tools {
		scanTool := tool
		mcpsdk.AddTool(server, &mcpsdk.Tool{
			Name:        "frameseven_v1_" + scanTool.Name,
			Title:       "Run " + scanTool.Name + " Scanner Tool",
			Description: "Run the Framework v1 " + scanTool.Name + " tool. " + scanTool.Description + ". Pass auth_cookies and/or auth_headers (and optional seed_endpoints) to run authenticated.",
			Annotations: &mcpsdk.ToolAnnotations{
				DestructiveHint: &destructiveHint,
			},
		}, V1ScanTool(scanTool.Name))
	}
}
