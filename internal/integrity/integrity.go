package integrity

import (
	"github.com/jasonli0226/depscan/internal/parser"
)

// Status represents the result of an integrity check.
type Status string

const (
	StatusOK       Status = "OK"
	StatusMismatch Status = "MISMATCH"
	StatusMissing  Status = "MISSING"
	StatusError    Status = "ERROR"
)

// IntegrityResult represents the integrity check result for a single dependency.
type IntegrityResult struct {
	Package   parser.Dependency
	Status    Status
	Algorithm string // "sha512", "h1", etc.
	Expected  string // expected hash from registry
	Actual    string // hash found in lockfile
	Error     string // error message if Status == ERROR
}

// Config controls integrity verification behavior.
type Config struct {
	Enabled bool
}

// DefaultConfig returns recommended defaults.
func DefaultConfig() Config {
	return Config{
		Enabled: true,
	}
}

// VerifyIntegrity checks dependency checksums against registry records.
// It dispatches to ecosystem-specific verifiers.
func VerifyIntegrity(deps []parser.Dependency, projectPath string, cfg Config) []IntegrityResult {
	if !cfg.Enabled || len(deps) == 0 {
		return nil
	}

	// Group dependencies by ecosystem
	goDeps := filterByEcosystem(deps, "Go")
	npmDeps := filterByEcosystem(deps, "npm")

	var results []IntegrityResult

	if len(goDeps) > 0 {
		results = append(results, verifyGoModules(goDeps, projectPath)...)
	}

	if len(npmDeps) > 0 {
		results = append(results, verifyNpmPackages(npmDeps, projectPath)...)
	}

	return results
}

func filterByEcosystem(deps []parser.Dependency, ecosystem string) []parser.Dependency {
	var filtered []parser.Dependency
	for _, d := range deps {
		if d.Ecosystem == ecosystem {
			filtered = append(filtered, d)
		}
	}
	return filtered
}
