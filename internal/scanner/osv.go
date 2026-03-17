package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jasonli0226/depscan/internal/parser"
)

// Vulnerability represents a CVE from OSV
type Vulnerability struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
}

// ScanResult represents the scan result for a single dependency
type ScanResult struct {
	Dependency      parser.Dependency
	Vulnerabilities []Vulnerability
	Error           error
}

// OSVRequest is the request body for OSV API
type OSVRequest struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version"`
}

// OSVPackage identifies a package
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVResponse is the response from OSV API
type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

// OSVVuln represents a vulnerability in OSV response
type OSVVuln struct {
	ID         string        `json:"id"`
	Summary    string        `json:"summary"`
	Aliases    []string      `json:"aliases"`
	Severities []OSVSeverity `json:"severity"`
}

// OSVSeverity represents severity info
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

const osvAPIURL = "https://api.osv.dev/v1/query"
const timeout = 10 * time.Second
const maxConcurrent = 5

var httpClient = &http.Client{Timeout: timeout}

// ScanDependencies scans all dependencies for vulnerabilities
func ScanDependencies(deps []parser.Dependency) []ScanResult {
	results := make([]ScanResult, len(deps))

	// Use semaphore pattern for concurrency limiting
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i, dep := range deps {
		wg.Add(1)
		go func(idx int, d parser.Dependency) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			vulns, err := queryOSV(d)
			results[idx] = ScanResult{
				Dependency:      d,
				Vulnerabilities: vulns,
				Error:           err,
			}
		}(i, dep)
	}

	wg.Wait()
	return results
}

// queryOSV queries the OSV API for a single dependency
func queryOSV(dep parser.Dependency) ([]Vulnerability, error) {
	reqBody := OSVRequest{
		Package: OSVPackage{
			Name:      dep.Name,
			Ecosystem: dep.Ecosystem,
		},
		Version: dep.Version,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	client := httpClient
	resp, err := client.Post(osvAPIURL, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("OSV API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	// Convert OSV vulnerabilities to our format
	vulns := make([]Vulnerability, 0, len(osvResp.Vulns))
	for _, v := range osvResp.Vulns {
		severity := extractSeverity(v.Severities)
		vulns = append(vulns, Vulnerability{
			ID:       v.ID,
			Summary:  v.Summary,
			Severity: severity,
		})
	}

	return vulns, nil
}

// extractSeverity extracts the highest severity level
func extractSeverity(severities []OSVSeverity) string {
	if len(severities) == 0 {
		return "UNKNOWN"
	}

	// Priority order: CRITICAL > HIGH > MEDIUM > LOW
	severityPriority := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	highest := "UNKNOWN"
	highestPriority := 0

	for _, s := range severities {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			// Parse CVSS score
			var score float64
			fmt.Sscanf(s.Score, "%f", &score)

			switch {
			case score >= 9.0:
				if severityPriority["CRITICAL"] > highestPriority {
					highest = "CRITICAL"
					highestPriority = severityPriority["CRITICAL"]
				}
			case score >= 7.0:
				if severityPriority["HIGH"] > highestPriority {
					highest = "HIGH"
					highestPriority = severityPriority["HIGH"]
				}
			case score >= 4.0:
				if severityPriority["MEDIUM"] > highestPriority {
					highest = "MEDIUM"
					highestPriority = severityPriority["MEDIUM"]
				}
			default:
				if severityPriority["LOW"] > highestPriority {
					highest = "LOW"
					highestPriority = severityPriority["LOW"]
				}
			}
		}
	}

	return highest
}
