// Package mcp exposes the FrameSeven MCP server.
package mcp

import (
	"context"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName  = "frameseven-mcp"
	serverBuild = "development"
)

// NewServer builds the FrameSeven MCP server.
func NewServer() *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    serverName,
		Version: serverBuild,
	}, nil)

	RegisterTools(server)

	return server
}

// Run starts the MCP server over stdin/stdout.
func Run(ctx context.Context) error {
	return NewServer().Run(ctx, &mcpsdk.StdioTransport{})
}
