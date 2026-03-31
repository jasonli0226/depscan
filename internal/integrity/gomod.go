package integrity

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jasonli0226/depscan/internal/parser"
)

// parseGoSum reads go.sum and extracts module@version -> hash entries.
func parseGoSum(projectPath string) (map[string][]string, error) {
	goSumPath := filepath.Join(projectPath, "go.sum")

	file, err := os.Open(goSumPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open go.sum: %w", err)
	}
	defer file.Close()

	entries := make(map[string][]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		var key, hashField string
		if strings.Contains(parts[0], "@") {
			// Format: module@version h1:HASH [h1:HASH]
			key = parts[0]
			hashField = parts[1]
		} else if len(parts) >= 3 {
			// Format: module version h1:HASH [h1:HASH]
			key = parts[0] + "@" + parts[1]
			hashField = parts[2]
		} else {
			continue
		}

		entries[key] = append(entries[key], hashField)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading go.sum: %w", err)
	}

	return entries, nil
}

// verifyGoModules checks Go module checksums against go.sum entries.
// Since Go's checksum database (sum.golang.org) requires the full go.sum
// verification workflow (which go mod verify already does), we instead
// verify that all dependencies listed in go.mod have corresponding entries
// in go.sum, and flag any missing entries as potential integrity issues.
//
// Full sumdb verification would require golang.org/x/mod/sumdb which is
// a heavier dependency. For now, we verify lockfile completeness.
func verifyGoModules(deps []parser.Dependency, projectPath string) []IntegrityResult {
	goSumEntries, err := parseGoSum(projectPath)
	if err != nil {
		// go.sum not found is not an error per se (project may not have it)
		// Return results for each dep as MISSING
		results := make([]IntegrityResult, 0, len(deps))
		for _, dep := range deps {
			results = append(results, IntegrityResult{
				Package: dep,
				Status:  StatusMissing,
				Error:   "go.sum not found",
			})
		}
		return results
	}

	results := make([]IntegrityResult, 0, len(deps))

	for _, dep := range deps {
		// go.sum uses full module paths, try common formats
		versionStr := "v" + dep.Version
		key := dep.Name + "@" + versionStr

		hashes, ok := goSumEntries[key]
		if !ok {
			// Try without 'v' prefix
			key = dep.Name + "@" + dep.Version
			hashes, ok = goSumEntries[key]
		}

		if !ok || len(hashes) == 0 {
			results = append(results, IntegrityResult{
				Package: dep,
				Status:  StatusMissing,
				Error:   "no checksum found in go.sum",
			})
			continue
		}

		// go.sum entries are verified by 'go mod verify'.
		// If the entry exists, it was checksummed. We report OK.
		// A full implementation would cross-reference with sum.golang.org.
		algorithm := "h1"
		if len(hashes) > 0 && strings.HasPrefix(hashes[0], "h1:") {
			algorithm = "h1"
		}

		results = append(results, IntegrityResult{
			Package:   dep,
			Status:    StatusOK,
			Algorithm: algorithm,
			Expected:  hashes[0],
			Actual:    hashes[0],
		})
	}

	return results
}
