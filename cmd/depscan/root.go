package depscan

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jasonli0226/depscan/internal/integrity"
	"github.com/jasonli0226/depscan/internal/output"
	"github.com/jasonli0226/depscan/internal/parser"
	"github.com/jasonli0226/depscan/internal/scanner"
	"github.com/jasonli0226/depscan/internal/scorer"
	"github.com/jasonli0226/depscan/internal/typosquat"
)

var (
	version    = "dev"
	outputFile string
)

var rootCmd = &cobra.Command{
	Use:     "depscan <project-path>",
	Short:   "Supply Chain Security Scanner for Go and Node.js dependencies",
	Long:    "Scan Go modules and NPM/PNPM packages for known vulnerabilities using OSV.dev",
	Version: version,
	Args:    cobra.ExactArgs(1),
	RunE:    runScan,
}

func init() {
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for JSON report")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	projectPath := args[0]

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	fmt.Printf("🔍 Scanning dependencies in: %s\n\n", absPath)

	var allDeps []parser.Dependency

	goDeps, err := parser.ParseGoModules(projectPath)
	if err == nil && len(goDeps) > 0 {
		fmt.Printf("📦 Found %d Go modules\n", len(goDeps))
		allDeps = append(allDeps, goDeps...)
	}

	npmDeps, err := parser.ParseNPMPackages(projectPath)
	if err == nil && len(npmDeps) > 0 {
		fmt.Printf("📦 Found %d NPM packages\n", len(npmDeps))
		allDeps = append(allDeps, npmDeps...)
	}

	pnpmDeps, err := parser.ParsePNPMPackages(projectPath)
	if err == nil && len(pnpmDeps) > 0 {
		fmt.Printf("📦 Found %d PNPM packages\n", len(pnpmDeps))
		allDeps = append(allDeps, pnpmDeps...)
	}

	if len(allDeps) == 0 {
		fmt.Println("⚠️  No dependencies found in project")
		return nil
	}

	fmt.Printf("\n🔍 Scanning %d dependencies for vulnerabilities...\n\n", len(allDeps))

	vulnResults := scanner.ScanDependencies(allDeps)

	typosquatCfg := typosquat.DefaultConfig()
	typosquatResults := typosquat.CheckTyposquat(allDeps, typosquatCfg)

	integrityCfg := integrity.DefaultConfig()
	integrityResults := integrity.VerifyIntegrity(allDeps, projectPath, integrityCfg)

	riskScore := scorer.CalculateRiskScoreWithAll(vulnResults, typosquatResults, integrityResults)

	totalVulns := 0
	for _, r := range vulnResults {
		totalVulns += len(r.Vulnerabilities)
	}

	if outputFile != "" {
		if err := output.WriteJSON(vulnResults, typosquatResults, integrityResults, projectPath, riskScore, outputFile); err != nil {
			return fmt.Errorf("failed to write JSON output: %w", err)
		}
		fmt.Printf("📄 JSON report saved to: %s\n\n", outputFile)
	}

	output.PrintTerminal(vulnResults, typosquatResults, integrityResults, riskScore, totalVulns)

	return nil
}
