package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type UVLock struct {
	Version  int         `toml:"version"`
	Packages []UVPackage `toml:"package"`
}

type UVPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

func ParseUVPackages(projectPath string) ([]Dependency, error) {
	lockPath := filepath.Join(projectPath, "uv.lock")

	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open uv.lock: %w", err)
	}

	var lockFile UVLock
	if err := toml.Unmarshal(data, &lockFile); err != nil {
		return nil, fmt.Errorf("invalid uv.lock format: %w", err)
	}

	seen := make(map[string]bool)
	var deps []Dependency

	for _, pkg := range lockFile.Packages {
		if !isValidUVPackage(pkg) {
			continue
		}

		key := pkg.Name + "@" + pkg.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, Dependency{
			Name:      pkg.Name,
			Version:   normalizeVersion(pkg.Version),
			Ecosystem: "PyPI",
		})
	}

	return deps, nil
}

func isValidUVPackage(pkg UVPackage) bool {
	return pkg.Name != "" && pkg.Version != ""
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	return version
}
