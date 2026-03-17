package output

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/jasonli0226/depscan/internal/scanner"
	"github.com/jasonli0226/depscan/internal/scorer"
)

// PrintTerminal prints the scan results to terminal with colors
func PrintTerminal(results []scanner.ScanResult, riskScore, totalVulns int) {
	bold := color.New(color.Bold)
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan)

	// Print vulnerability details
	for _, result := range results {
		if len(result.Vulnerabilities) == 0 {
			continue
		}

		// Package header
		bold.Printf("📦 %s@%s", result.Dependency.Name, result.Dependency.Version)
		cyan.Printf(" [%s]\n", result.Dependency.Ecosystem)

		if result.Error != nil {
			red.Printf("   ❌ Error: %v\n", result.Error)
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			severityColor := getSeverityColor(vuln.Severity)
			severityColor.Printf("   ❌ %s [%s] ", vuln.ID, vuln.Severity)
			fmt.Printf("%s\n", truncate(vuln.Summary, 60))
		}
		fmt.Println()
	}

	// Summary
	fmt.Println(strings.Repeat("─", 50))
	bold.Println("📊 Summary")
	fmt.Println(strings.Repeat("─", 50))

	// Total vulnerabilities
	if totalVulns > 0 {
		red.Printf("   Vulnerabilities: %d\n", totalVulns)
	} else {
		green.Println("   Vulnerabilities: 0 ✅")
	}

	// Risk score
	riskLevel := scorer.RiskLevel(riskScore)
	riskColor := getRiskColor(riskLevel)
	riskColor.Printf("   Risk Score: %d/100 [%s]\n", riskScore, riskLevel)

	fmt.Println()

	// Final verdict
	if totalVulns > 0 {
		red.Println("❌ Action required: Fix vulnerabilities before deploying!")
	} else {
		green.Println("✅ All clear! No known vulnerabilities found.")
	}
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
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
