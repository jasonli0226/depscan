package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PackageLock represents npm package-lock.json structure
type PackageLock struct {
	Version      int                `json:"lockfileVersion"`
	Packages     map[string]Package `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

// Package represents a single npm package
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParseNPMPackages parses package-lock.json and extracts dependencies
func ParseNPMPackages(projectPath string) ([]Dependency, error) {
	lockPath := filepath.Join(projectPath, "package-lock.json")

	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open package-lock.json: %w", err)
	}

	var lockFile PackageLock
	if err := json.Unmarshal(data, &lockFile); err != nil {
		return nil, fmt.Errorf("invalid package-lock.json format: %w", err)
	}

	seen := make(map[string]bool)
	var deps []Dependency

	// Lockfile v2+ uses "packages"
	if lockFile.Packages != nil {
		for pkgPath, pkg := range lockFile.Packages {
			// Skip root package (empty string key) and packages without version
			if pkgPath == "" || pkg.Version == "" {
				continue
			}

			name := pkg.Name
			if name == "" {
				// Fallback: extract from path (npm always uses forward slashes)
				parts := strings.Split(pkgPath, "/")
				if len(parts) > 0 {
					name = parts[len(parts)-1]
				}
			}

			if name == "" {
				continue
			}

			// Deduplicate by name+version
			key := name + "@" + pkg.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			deps = append(deps, Dependency{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
			})
		}
	}

	// Lockfile v1 uses "dependencies"
	if lockFile.Dependencies != nil && len(deps) == 0 {
		for name, dep := range lockFile.Dependencies {
			key := name + "@" + dep.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			deps = append(deps, Dependency{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "npm",
			})
		}
	}

	return deps, nil
}
