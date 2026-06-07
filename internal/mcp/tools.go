package mcp

import (
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

// RegisterTools adds the FrameSeven MCP tools.
func RegisterTools(server *mcpsdk.Server) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_list_modules",
		Description: "List Framework v1 scanner modules and whether each module runs by default.",
	}, V1ListModules)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_normalize_modules",
		Description: "Validate and normalize a Framework v1 module selection without starting a scan.",
	}, V1NormalizeModules)

	for _, module := range scanner.Modules {
		mcpsdk.AddTool(server, &mcpsdk.Tool{
			Name:        "frameseven_v1_" + module.Name,
			Description: "Run the Framework v1 " + module.Name + " module. " + module.Description + ".",
		}, V1ScanModule(module.Name))
	}
}
