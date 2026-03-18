package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func ParsePNPMPackages(projectPath string) ([]Dependency, error) {
	lockPath := filepath.Join(projectPath, "pnpm-lock.yaml")

	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open pnpm-lock.yaml: %w", err)
	}

	deps := parsePNPMLockfileV9(data)

	if len(deps) == 0 {
		deps = parsePNPMPackagesSection(data)
	}

	return deps, nil
}

func parsePNPMLockfileV9(data []byte) []Dependency {
	seen := make(map[string]bool)
	var deps []Dependency

	lines := strings.Split(string(data), "\n")
	inImporters := false
	inImporterBlock := false
	inDepsSection := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimRight(line, "\r")

		if trimmed == "importers:" {
			inImporters = true
			continue
		}

		if !inImporters {
			continue
		}

		if strings.HasPrefix(trimmed, "  ") && !strings.HasPrefix(trimmed, "    ") && strings.HasSuffix(trimmed, ":") {
			inImporterBlock = true
			inDepsSection = false
			continue
		}

		if !inImporterBlock {
			continue
		}

		if trimmed == "    dependencies:" || trimmed == "    devDependencies:" {
			inDepsSection = true
			continue
		}

		if strings.HasPrefix(trimmed, "    ") && !strings.HasPrefix(trimmed, "      ") && trimmed != "" {
			inDepsSection = false
			continue
		}

		if !inDepsSection {
			continue
		}

		if strings.HasPrefix(trimmed, "      ") && !strings.HasPrefix(trimmed, "        ") {
			name := extractDepName(trimmed)
			if name == "" {
				continue
			}

			version := ""
			for j := i + 1; j < len(lines) && strings.HasPrefix(lines[j], "        "); j++ {
				verLine := strings.TrimRight(lines[j], "\r")
				if strings.HasPrefix(verLine, "        version: ") {
					version = strings.TrimPrefix(verLine, "        version: ")
					version = extractVersion(version)
					break
				}
			}

			if version != "" {
				key := name + "@" + version
				if !seen[key] {
					seen[key] = true
					deps = append(deps, Dependency{
						Name:      name,
						Version:   version,
						Ecosystem: "npm",
					})
				}
			}
		}

		if !strings.HasPrefix(trimmed, " ") && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			break
		}
	}

	return deps
}

func extractDepName(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimSuffix(line, ":")

	if strings.HasPrefix(line, "'") && strings.HasSuffix(line, "'") {
		line = strings.Trim(line, "'")
	}

	return line
}

func extractVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.Trim(version, `'"`)

	if idx := strings.Index(version, "("); idx != -1 {
		version = version[:idx]
	}

	return version
}

func parsePNPMPackagesSection(data []byte) []Dependency {
	seen := make(map[string]bool)
	var deps []Dependency

	lines := strings.Split(string(data), "\n")
	inPackages := false

	pkgPattern := regexp.MustCompile(`^  (/[^:]+|@[^/]+/[^:]+|[^@/]+@[^:]+):`)

	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")

		if trimmed == "packages:" {
			inPackages = true
			continue
		}

		if inPackages && !strings.HasPrefix(trimmed, "  /") && !strings.HasPrefix(trimmed, "  @") {
			if !strings.HasPrefix(trimmed, "    ") && trimmed != "" {
				inPackages = false
			}
		}

		if !inPackages {
			continue
		}

		matches := pkgPattern.FindStringSubmatch(trimmed)
		if len(matches) < 2 {
			continue
		}

		pkgKey := strings.Trim(matches[1], "/")

		name, version := parsePNPMPackageKey(pkgKey)
		if name == "" || version == "" {
			continue
		}

		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}

	return deps
}

func parsePNPMPackageKey(key string) (name, version string) {
	if strings.HasPrefix(key, "@") {
		parts := strings.SplitN(key, "/", 3)
		if len(parts) >= 3 {
			scope := parts[0]
			namePart := parts[1]
			rest := parts[2]

			name = scope + "/" + namePart

			if idx := strings.Index(rest, "_"); idx != -1 {
				version = rest[:idx]
			} else {
				version = rest
			}

			version = strings.SplitN(version, "@", 2)[0]
			version = strings.TrimSuffix(version, "(")
		}
	} else {
		parts := strings.SplitN(key, "@", 2)
		if len(parts) >= 2 {
			name = parts[0]
			version = parts[1]

			if idx := strings.Index(version, "_"); idx != -1 {
				version = version[:idx]
			}
			version = strings.TrimSuffix(version, "(")
		}
	}

	return name, version
}
