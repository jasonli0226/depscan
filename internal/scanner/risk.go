package scanner

// SeverityScore returns the risk score for a severity level
func SeverityScore(severity string) int {
	switch severity {
	case "CRITICAL":
		return 30
	case "HIGH":
		return 20
	case "MEDIUM":
		return 10
	case "LOW":
		return 5
	default:
		return 5
	}
}
