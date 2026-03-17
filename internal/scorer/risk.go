package scorer

import (
	"github.com/jasonli0226/depscan/internal/scanner"
)

// CalculateRiskScore calculates an overall risk score (0-100) for the scan results
func CalculateRiskScore(results []scanner.ScanResult) int {
	totalScore := 0

	for _, result := range results {
		for _, vuln := range result.Vulnerabilities {
			totalScore += scanner.SeverityScore(vuln.Severity)
		}
	}

	// Cap at 100
	if totalScore > 100 {
		return 100
	}
	return totalScore
}

// RiskLevel returns a human-readable risk level
func RiskLevel(score int) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 40:
		return "HIGH"
	case score >= 20:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}
