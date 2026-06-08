package mcp

import (
	"encoding/json"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDescribeRequestToolCall(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"target":               "http://testaspnet.vulnweb.com",
		"active_scan_accepted": true,
		"extra_tools":          []string{"recon"},
		"custom_payloads":      []string{"' OR 1=1--"},
	})

	identity, detail := describeRequest(&mcpsdk.CallToolParamsRaw{
		Name:      "frameseven_v1_sqli",
		Arguments: args,
	})

	if identity != " tool=frameseven_v1_sqli" {
		t.Fatalf("identity = %q", identity)
	}

	want := " target=http://testaspnet.vulnweb.com extra_tools=[recon] active_scan_accepted=true custom_payloads=1"
	if detail != want {
		t.Fatalf("detail = %q, want %q", detail, want)
	}
}

func TestDescribeRequestReadResource(t *testing.T) {
	identity, detail := describeRequest(&mcpsdk.ReadResourceParams{
		URI: "skill://hack-skills/v1/sqli-sql-injection/SKILL.md",
	})

	if identity != " uri=skill://hack-skills/v1/sqli-sql-injection/SKILL.md" {
		t.Fatalf("identity = %q", identity)
	}

	if detail != "" {
		t.Fatalf("detail = %q, want empty", detail)
	}
}

func TestDescribeToolResultCounts(t *testing.T) {
	result := &mcpsdk.CallToolResult{
		StructuredContent: scanToolOutput{
			SelectedTools: []string{"recon", "sqli"},
			FindingsCount: 3,
			ErrorsCount:   0,
			Target:        "http://testaspnet.vulnweb.com",
		},
	}

	got := describeResult(result)

	want := " selected=[recon sqli] findings=3 errors=0"
	if got != want {
		t.Fatalf("describeResult = %q, want %q", got, want)
	}
}

func TestDescribeResultListSizes(t *testing.T) {
	tools := describeResult(&mcpsdk.ListToolsResult{
		Tools: []*mcpsdk.Tool{{Name: "a"}, {Name: "b"}},
	})

	if tools != " tools=2" {
		t.Fatalf("list tools = %q", tools)
	}

	resources := describeResult(&mcpsdk.ListResourcesResult{
		Resources: []*mcpsdk.Resource{{URI: "skill://x"}},
	})

	if resources != " resources=1" {
		t.Fatalf("list resources = %q", resources)
	}
}
