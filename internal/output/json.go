package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jasonli0226/depscan/internal/scanner"
	"github.com/jasonli0226/depscan/internal/scorer"
)

// Report is the JSON output structure
type Report struct {
	ScanTime             string      `json:"scan_time"`
	ProjectPath          string      `json:"project_path"`
	TotalDependencies    int         `json:"total_dependencies"`
	VulnerabilitiesFound int         `json:"vulnerabilities_found"`
	RiskScore            int         `json:"risk_score"`
	RiskLevel            string      `json:"risk_level"`
	Results              []PkgResult `json:"results"`
}

// PkgResult is a single package result in the JSON output
type PkgResult struct {
	Package         string     `json:"package"`
	Version         string     `json:"version"`
	Ecosystem       string     `json:"ecosystem"`
	Vulnerabilities []VulnInfo `json:"vulnerabilities,omitempty"`
	Error           string     `json:"error,omitempty"`
}

// VulnInfo is vulnerability info for JSON output
type VulnInfo struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

// WriteJSON writes the scan results to a JSON file
func WriteJSON(results []scanner.ScanResult, projectPath string, riskScore int, outputPath string) error {
	pkgResults := make([]PkgResult, 0, len(results))
	totalDeps := 0
	totalVulns := 0

	for _, r := range results {
		totalDeps++

		pkg := PkgResult{
			Package:   r.Dependency.Name,
			Version:   r.Dependency.Version,
			Ecosystem: r.Dependency.Ecosystem,
		}

		if r.Error != nil {
			pkg.Error = r.Error.Error()
		} else if len(r.Vulnerabilities) > 0 {
			pkg.Vulnerabilities = make([]VulnInfo, len(r.Vulnerabilities))
			for i, v := range r.Vulnerabilities {
				pkg.Vulnerabilities[i] = VulnInfo{
					ID:       v.ID,
					Severity: v.Severity,
					Summary:  v.Summary,
				}
				totalVulns++
			}
		}

		pkgResults = append(pkgResults, pkg)
	}

	report := Report{
		ScanTime:             time.Now().UTC().Format(time.RFC3339),
		ProjectPath:          projectPath,
		TotalDependencies:    totalDeps,
		VulnerabilitiesFound: totalVulns,
		RiskScore:            riskScore,
		RiskLevel:            scorer.RiskLevel(riskScore),
		Results:              pkgResults,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
