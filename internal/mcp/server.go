// Package mcp exposes the FrameSeven MCP server.
package mcp

import (
	"context"
	"log"
	"net/http"
	"time"

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

	server.AddReceivingMiddleware(createLoggingMiddleware())

	RegisterTools(server)

	return server
}

// Run starts the MCP server over stdin/stdout.
func Run(ctx context.Context) error {
	log.Printf("MCP server starting on stdio transport")
	return NewServer().Run(ctx, &mcpsdk.StdioTransport{})
}

// NewStreamableHTTPHandler builds the HTTP handler used by remote MCP clients.
func NewStreamableHTTPHandler() http.Handler {
	server := NewServer()

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return server
	}, nil))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	return mux
}

// RunHTTP starts the MCP server over Streamable HTTP.
func RunHTTP(ctx context.Context, addr string) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           NewStreamableHTTPHandler(),
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("MCP server listening on http://%s", addr)

	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}

	return err
}
