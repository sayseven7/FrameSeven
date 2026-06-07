package main

import (
	"context"
	"log"

	framesevenmcp "github.com/sayseven7/frameseven/internal/mcp"
)

func main() {
	if err := framesevenmcp.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
