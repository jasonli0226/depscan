package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Dependency represents a parsed dependency
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
}

// ParseGoModules parses go.mod file and extracts dependencies
func ParseGoModules(projectPath string) ([]Dependency, error) {
	goModPath := filepath.Join(projectPath, "go.mod")

	file, err := os.Open(goModPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open go.mod: %w", err)
	}
	defer file.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(file)
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Handle require block
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}

		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Handle single-line require
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
			line = strings.TrimSpace(line)
		}

		// Parse module line: module/path v1.2.3
		if inRequire || strings.Contains(line, " v") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[0]
				version := strings.TrimPrefix(parts[1], "v")

				// Skip indirect dependencies marker
				if len(parts) > 2 && parts[2] == "// indirect" {
					// Still include it, just note it's indirect
				}

				deps = append(deps, Dependency{
					Name:      name,
					Version:   version,
					Ecosystem: "Go",
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading go.mod: %w", err)
	}

	return deps, nil
}
