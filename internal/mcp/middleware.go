package mcp

import (
	"context"
	"log"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func createLoggingMiddleware() mcpsdk.Middleware {
	return func(next mcpsdk.MethodHandler) mcpsdk.MethodHandler {
		return func(ctx context.Context, method string, req mcpsdk.Request) (mcpsdk.Result, error) {
			started := time.Now()
			sessionID := req.GetSession().ID()

			log.Printf("MCP request session=%s method=%s", sessionID, method)

			result, err := next(ctx, method, req)
			duration := time.Since(started).Round(time.Millisecond)
			if err != nil {
				log.Printf("MCP response session=%s method=%s status=error duration=%s error=%v", sessionID, method, duration, err)
				return result, err
			}

			log.Printf("MCP response session=%s method=%s status=ok duration=%s", sessionID, method, duration)

			return result, nil
		}
	}
}
