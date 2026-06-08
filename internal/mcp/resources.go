package mcp

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// skillsFS embeds the vendored yaklang/hack-skills pentest playbooks so the MCP
// server can expose them as resources without any network access at runtime.
//
//go:embed all:skills
var skillsFS embed.FS

const (
	skillsRoot     = "skills"
	skillURIPrefix = "skill://hack-skills/v1/"
	skillMIMEType  = "text/markdown"
)

// RegisterResources exposes the vendored hack-skills pentest playbooks as
// Framework v1 MCP resources. Every Markdown file under skills/ becomes one
// resource so agents can read both the main SKILL.md playbooks and their
// companion references.
func RegisterResources(server *mcpsdk.Server) {
	paths, err := skillMarkdownPaths()
	if err != nil {
		panic(fmt.Sprintf("RegisterResources: %v", err))
	}

	for _, p := range paths {
		resource, content, err := buildSkillResource(p)
		if err != nil {
			panic(fmt.Sprintf("RegisterResources: %s: %v", p, err))
		}

		server.AddResource(resource, skillResourceHandler(resource.URI, content))
	}
}

// skillMarkdownPaths returns every embedded skill Markdown file path in a
// stable order.
func skillMarkdownPaths() ([]string, error) {
	var paths []string

	err := fs.WalkDir(skillsFS, skillsRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if strings.HasSuffix(p, ".md") {
			paths = append(paths, p)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(paths)

	return paths, nil
}

// buildSkillResource builds the resource metadata and reads the file content for
// one embedded skill Markdown file.
func buildSkillResource(embedPath string) (*mcpsdk.Resource, string, error) {
	data, err := skillsFS.ReadFile(embedPath)
	if err != nil {
		return nil, "", err
	}

	content := string(data)
	rel := strings.TrimPrefix(embedPath, skillsRoot+"/")

	name, description := skillMetadata(rel, content)

	resource := &mcpsdk.Resource{
		Name:        name,
		Title:       skillTitle(rel),
		Description: description,
		MIMEType:    skillMIMEType,
		URI:         skillURIPrefix + rel,
	}

	return resource, content, nil
}

// skillMetadata returns the resource name and description for a skill file. The
// main SKILL.md files carry YAML frontmatter with name and description; the
// companion files do not, so we derive both from their path.
func skillMetadata(rel, content string) (string, string) {
	name, description := parseFrontmatter(content)

	if name == "" {
		name = strings.TrimSuffix(rel, ".md")
	}

	if description == "" {
		skill := path.Dir(rel)
		file := path.Base(rel)
		description = fmt.Sprintf("Companion reference (%s) for the %s skill.", file, skill)
	}

	return name, description
}

// skillTitle returns a human-readable title for a skill file based on its path.
func skillTitle(rel string) string {
	skill := path.Dir(rel)
	file := path.Base(rel)

	if file == "SKILL.md" {
		return skill
	}

	return skill + ": " + strings.TrimSuffix(file, ".md")
}

// parseFrontmatter extracts the name and description from a leading YAML
// frontmatter block. It supports inline scalars and the folded scalars (">-",
// ">", "|") used by the hack-skills descriptions. It returns empty strings when
// no frontmatter is present.
func parseFrontmatter(content string) (string, string) {
	if !strings.HasPrefix(content, "---\n") {
		return "", ""
	}

	rest := content[len("---\n"):]

	end := strings.Index(rest, "\n---")
	if end == -1 {
		return "", ""
	}

	lines := strings.Split(rest[:end], "\n")

	var name string
	var description string

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		if value, ok := strings.CutPrefix(line, "name:"); ok {
			name = strings.TrimSpace(value)
			continue
		}

		if value, ok := strings.CutPrefix(line, "description:"); ok {
			value = strings.TrimSpace(value)

			if value == ">-" || value == ">" || value == "|" || value == "|-" {
				description = joinFoldedScalar(lines[i+1:])
				continue
			}

			description = value
		}
	}

	return name, description
}

// joinFoldedScalar collapses the indented continuation lines of a YAML folded
// scalar into a single space-separated string.
func joinFoldedScalar(lines []string) string {
	var parts []string

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			break
		}

		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}

		parts = append(parts, strings.TrimSpace(line))
	}

	return strings.Join(parts, " ")
}

// skillResourceHandler returns a handler that serves the embedded Markdown for
// one skill resource.
func skillResourceHandler(uri, content string) mcpsdk.ResourceHandler {
	return func(ctx context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		return &mcpsdk.ReadResourceResult{
			Contents: []*mcpsdk.ResourceContents{
				{
					URI:      uri,
					MIMEType: skillMIMEType,
					Text:     content,
				},
			},
		}, nil
	}
}
