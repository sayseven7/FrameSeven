package mcp

import (
	"strings"
	"testing"
)

func TestSkillMarkdownPathsIncludeKnownSkills(t *testing.T) {
	paths, err := skillMarkdownPaths()
	if err != nil {
		t.Fatalf("skillMarkdownPaths: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("expected at least one embedded skill file")
	}

	var found bool
	for _, p := range paths {
		if p == "skills/sqli-sql-injection/SKILL.md" {
			found = true
		}
	}

	if !found {
		t.Fatal("expected the sqli-sql-injection SKILL.md to be embedded")
	}
}

func TestBuildSkillResourceUsesFrontmatter(t *testing.T) {
	resource, content, err := buildSkillResource("skills/sqli-sql-injection/SKILL.md")
	if err != nil {
		t.Fatalf("buildSkillResource: %v", err)
	}

	if resource.Name != "sqli-sql-injection" {
		t.Fatalf("name = %q, want sqli-sql-injection", resource.Name)
	}

	if resource.URI != "skill://hack-skills/v1/sqli-sql-injection/SKILL.md" {
		t.Fatalf("uri = %q", resource.URI)
	}

	if resource.MIMEType != skillMIMEType {
		t.Fatalf("mime = %q, want %q", resource.MIMEType, skillMIMEType)
	}

	if !strings.Contains(resource.Description, "SQL injection") {
		t.Fatalf("description missing frontmatter text: %q", resource.Description)
	}

	if content == "" {
		t.Fatal("expected non-empty resource content")
	}
}

func TestBuildSkillResourceCompanionFallback(t *testing.T) {
	resource, _, err := buildSkillResource("skills/sqli-sql-injection/SCENARIOS.md")
	if err != nil {
		t.Fatalf("buildSkillResource: %v", err)
	}

	if resource.Name != "sqli-sql-injection/SCENARIOS" {
		t.Fatalf("name = %q, want sqli-sql-injection/SCENARIOS", resource.Name)
	}

	if !strings.Contains(resource.Description, "Companion reference") {
		t.Fatalf("description = %q, want companion fallback", resource.Description)
	}
}

func TestParseFrontmatterFoldedScalar(t *testing.T) {
	content := "---\nname: demo\ndescription: >-\n  First line\n  second line\n---\n\n# Body\n"

	name, description := parseFrontmatter(content)

	if name != "demo" {
		t.Fatalf("name = %q, want demo", name)
	}

	if description != "First line second line" {
		t.Fatalf("description = %q, want %q", description, "First line second line")
	}
}

func TestParseFrontmatterNone(t *testing.T) {
	name, description := parseFrontmatter("# No frontmatter\n")

	if name != "" || description != "" {
		t.Fatalf("expected empty metadata, got name=%q description=%q", name, description)
	}
}

func TestRegisterResourcesDoesNotPanic(t *testing.T) {
	server := NewServer()

	if server == nil {
		t.Fatal("expected server")
	}
}
