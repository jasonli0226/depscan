package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jasonli0226/depscan/internal/integrity"
	"github.com/jasonli0226/depscan/internal/scanner"
	"github.com/jasonli0226/depscan/internal/scorer"
	"github.com/jasonli0226/depscan/internal/typosquat"
)

// Report is the full JSON output structure.
type Report struct {
	ScanTime             string             `json:"scan_time"`
	ProjectPath          string             `json:"project_path"`
	TotalDependencies    int                `json:"total_dependencies"`
	VulnerabilitiesFound int                `json:"vulnerabilities_found"`
	RiskScore            int                `json:"risk_score"`
	RiskLevel            string             `json:"risk_level"`
	TyposquatWarnings    []TyposquatWarning `json:"typosquat_warnings,omitempty"`
	IntegrityResults     []IntegrityInfo    `json:"integrity_results,omitempty"`
	Results              []PkgResult        `json:"results"`
}

// TyposquatWarning represents a typosquat finding in JSON output.
type TyposquatWarning struct {
	Package      string  `json:"package"`
	Version      string  `json:"version"`
	Ecosystem    string  `json:"ecosystem"`
	ConfusedWith string  `json:"confused_with"`
	Similarity   float64 `json:"similarity"`
	Technique    string  `json:"technique"`
}

// IntegrityInfo represents an integrity check result in JSON output.
type IntegrityInfo struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Status    string `json:"status"`
	Algorithm string `json:"algorithm,omitempty"`
	Expected  string `json:"expected,omitempty"`
	Actual    string `json:"actual,omitempty"`
	Error     string `json:"error,omitempty"`
}

// PkgResult is a single package vulnerability result in JSON output.
type PkgResult struct {
	Package         string     `json:"package"`
	Version         string     `json:"version"`
	Ecosystem       string     `json:"ecosystem"`
	Vulnerabilities []VulnInfo `json:"vulnerabilities,omitempty"`
	Error           string     `json:"error,omitempty"`
}

// VulnInfo is vulnerability info for JSON output.
type VulnInfo struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

// WriteJSON writes the full scan results to a JSON file.
func WriteJSON(
	vulnResults []scanner.ScanResult,
	typosquatResults []typosquat.TyposquatResult,
	integrityResults []integrity.IntegrityResult,
	projectPath string,
	riskScore int,
	outputPath string,
) error {
	pkgResults := make([]PkgResult, 0, len(vulnResults))
	totalDeps := 0
	totalVulns := 0

	for _, r := range vulnResults {
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

	// Build typosquat warnings
	typoWarnings := make([]TyposquatWarning, 0, len(typosquatResults))
	for _, r := range typosquatResults {
		typoWarnings = append(typoWarnings, TyposquatWarning{
			Package:      r.Package.Name,
			Version:      r.Package.Version,
			Ecosystem:    r.Package.Ecosystem,
			ConfusedWith: r.ConfusedWith,
			Similarity:   r.Similarity,
			Technique:    r.Technique,
		})
	}

	// Build integrity results
	intInfo := make([]IntegrityInfo, 0, len(integrityResults))
	for _, r := range integrityResults {
		intInfo = append(intInfo, IntegrityInfo{
			Package:   r.Package.Name,
			Version:   r.Package.Version,
			Ecosystem: r.Package.Ecosystem,
			Status:    string(r.Status),
			Algorithm: r.Algorithm,
			Expected:  r.Expected,
			Actual:    r.Actual,
			Error:     r.Error,
		})
	}

	report := Report{
		ScanTime:             time.Now().UTC().Format(time.RFC3339),
		ProjectPath:          projectPath,
		TotalDependencies:    totalDeps,
		VulnerabilitiesFound: totalVulns,
		RiskScore:            riskScore,
		RiskLevel:            scorer.RiskLevel(riskScore),
		TyposquatWarnings:    typoWarnings,
		IntegrityResults:     intInfo,
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
