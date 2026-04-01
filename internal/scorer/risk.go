package scorer

import (
	"github.com/jasonli0226/depscan/internal/integrity"
	"github.com/jasonli0226/depscan/internal/scanner"
	"github.com/jasonli0226/depscan/internal/typosquat"
)

// Points assigned per check type
const (
	pointsTyposquat = 15 // HIGH equivalent
	pointsIntegrity = 30 // CRITICAL equivalent
)

// CalculateRiskScoreWithAll calculates risk from all check types:
// OSV vulnerabilities, typosquat warnings, and integrity failures.
func CalculateRiskScoreWithAll(
	vulnResults []scanner.ScanResult,
	typosquatResults []typosquat.TyposquatResult,
	integrityResults []integrity.IntegrityResult,
) int {
	totalScore := 0

	// OSV vulnerabilities
	for _, result := range vulnResults {
		for _, vuln := range result.Vulnerabilities {
			totalScore += scanner.SeverityScore(vuln.Severity)
		}
	}

	// Typosquat hits
	totalScore += len(typosquatResults) * pointsTyposquat

	// Integrity failures
	for _, r := range integrityResults {
		if r.Status == integrity.StatusMismatch {
			totalScore += pointsIntegrity
		}
	}

	if totalScore > 100 {
		return 100
	}
	return totalScore
}

// RiskLevel returns a human-readable risk level.
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
