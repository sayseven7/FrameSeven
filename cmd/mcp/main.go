// Package main implements the frameseven MCP server entry point. It starts
// either a stdio or HTTP transport for the FrameSeven MCP server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	framesevenmcp "github.com/sayseven7/frameseven/internal/mcp"
)

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	if err := run(context.Background(), opts); err != nil {
		log.Fatal(err)
	}
}

type options struct {
	transport string
	addr      string
}

func parseOptions(args []string) (options, error) {
	opts := options{}
	flags := flag.NewFlagSet("frameseven-mcp", flag.ContinueOnError)

	flags.StringVar(&opts.transport, "transport", "stdio", "MCP transport: stdio or http")
	flags.StringVar(&opts.addr, "addr", "127.0.0.1:8080", "HTTP listen address used with -transport http")

	if err := flags.Parse(args); err != nil {
		return options{}, err
	}

	if flags.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	return opts, nil
}

func run(ctx context.Context, opts options) error {
	switch opts.transport {
	case "stdio":
		return framesevenmcp.Run(ctx)
	case "http":
		return framesevenmcp.RunHTTP(ctx, opts.addr)
	default:
		return fmt.Errorf("unknown transport %q", opts.transport)
	}
}
