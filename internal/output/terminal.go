package output

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/jasonli0226/depscan/internal/integrity"
	"github.com/jasonli0226/depscan/internal/scanner"
	"github.com/jasonli0226/depscan/internal/scorer"
	"github.com/jasonli0226/depscan/internal/typosquat"
)

// PrintTerminal prints the full scan results to terminal with colors.
func PrintTerminal(
	vulnResults []scanner.ScanResult,
	typosquatResults []typosquat.TyposquatResult,
	integrityResults []integrity.IntegrityResult,
	riskScore, totalVulns int,
) {
	bold := color.New(color.Bold)
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)

	// Vulnerability details
	for _, result := range vulnResults {
		if len(result.Vulnerabilities) == 0 {
			continue
		}

		bold.Printf("  %s@%s", result.Dependency.Name, result.Dependency.Version)
		cyan.Printf(" [%s]\n", result.Dependency.Ecosystem)

		if result.Error != nil {
			red.Printf("   Error: %v\n", result.Error)
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			severityColor := getSeverityColor(vuln.Severity)
			severityColor.Printf("   [VULN] %s [%s] ", vuln.ID, vuln.Severity)
			fmt.Printf("%s\n", truncate(vuln.Summary, 60))
		}
		fmt.Println()
	}

	// Typosquat warnings
	if len(typosquatResults) > 0 {
		yellow.Println("-- Typosquat Warnings --")
		for _, r := range typosquatResults {
			yellow.Printf("  [TYPO] %s@%s [%s]\n", r.Package.Name, r.Package.Version, r.Package.Ecosystem)
			fmt.Printf("    Confused with: %s (similarity: %.0f%%, technique: %s)\n",
				r.ConfusedWith, r.Similarity*100, r.Technique)
		}
		fmt.Println()
	}

	// Integrity results
	integrityIssues := filterIntegrityIssues(integrityResults)
	if len(integrityIssues) > 0 {
		red.Println("-- Integrity Issues --")
		for _, r := range integrityIssues {
			red.Printf("  [INTEGRITY] %s@%s [%s] %s\n",
				r.Package.Name, r.Package.Version, r.Package.Ecosystem, r.Status)
			if r.Error != "" {
				fmt.Printf("    %s\n", r.Error)
			}
		}
		fmt.Println()
	}

	// Summary
	fmt.Println(strings.Repeat("-", 50))
	bold.Println("Summary")
	fmt.Println(strings.Repeat("-", 50))

	// Vulnerabilities
	if totalVulns > 0 {
		red.Printf("  Vulnerabilities: %d\n", totalVulns)
	} else {
		green.Println("  Vulnerabilities: 0")
	}

	// Typosquat
	if len(typosquatResults) > 0 {
		yellow.Printf("  Typosquat warnings: %d\n", len(typosquatResults))
	} else {
		green.Println("  Typosquat warnings: 0")
	}

	// Integrity
	if len(integrityIssues) > 0 {
		red.Printf("  Integrity issues: %d\n", len(integrityIssues))
	} else {
		green.Println("  Integrity issues: 0")
	}

	// Risk score
	riskLevel := scorer.RiskLevel(riskScore)
	riskColor := getRiskColor(riskLevel)
	riskColor.Printf("  Risk Score: %d/100 [%s]\n", riskScore, riskLevel)
	fmt.Println()

	// Final verdict
	totalIssues := totalVulns + len(typosquatResults) + len(integrityIssues)
	if totalIssues > 0 {
		red.Printf("  Action required: %d issues found before deploying!\n", totalIssues)
	} else {
		green.Println("  All clear! No issues found.")
	}
}

func filterIntegrityIssues(results []integrity.IntegrityResult) []integrity.IntegrityResult {
	var issues []integrity.IntegrityResult
	for _, r := range results {
		if r.Status != integrity.StatusOK {
			issues = append(issues, r)
		}
	}
	return issues
}

func getSeverityColor(severity string) *color.Color {
	switch severity {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold)
	case "HIGH":
		return color.New(color.FgRed)
	case "MEDIUM":
		return color.New(color.FgYellow)
	case "LOW":
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}

func getRiskColor(level string) *color.Color {
	switch level {
	case "CRITICAL":
		return color.New(color.BgRed, color.FgWhite, color.Bold)
	case "HIGH":
		return color.New(color.FgRed, color.Bold)
	case "MEDIUM":
		return color.New(color.FgYellow, color.Bold)
	case "LOW":
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgGreen, color.Bold)
	}
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-3]) + "..."
}
