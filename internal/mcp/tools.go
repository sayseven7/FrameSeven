package mcp

import (
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

// RegisterTools adds the FrameSeven MCP tools.
func RegisterTools(server *mcpsdk.Server) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_list_tools",
		Description: "List Framework v1 scanner tools and whether each tool runs by default.",
	}, V1ListTools)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_normalize_tools",
		Description: "Validate and normalize a Framework v1 tool selection without starting a scan.",
	}, V1NormalizeTools)

	for _, tool := range scanner.Tools {
		mcpsdk.AddTool(server, &mcpsdk.Tool{
			Name:        "frameseven_v1_" + tool.Name,
			Description: "Run the Framework v1 " + tool.Name + " tool. " + tool.Description + ".",
		}, V1ScanTool(tool.Name))
	}
}
