package integrity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonli0226/depscan/internal/parser"
)

func TestVerifyIntegrity(t *testing.T) {
	t.Run("returns empty when disabled", func(t *testing.T) {
		deps := []parser.Dependency{
			{Name: "express", Version: "4.18.0", Ecosystem: "npm"},
		}
		cfg := Config{Enabled: false}
		results := VerifyIntegrity(deps, "/nonexistent", cfg)
		if len(results) != 0 {
			t.Errorf("expected 0 results when disabled, got %d", len(results))
		}
	})

	t.Run("returns empty for nil deps", func(t *testing.T) {
		results := VerifyIntegrity(nil, "/nonexistent", DefaultConfig())
		if len(results) != 0 {
			t.Errorf("expected 0 results for nil deps, got %d", len(results))
		}
	})

	t.Run("go modules missing go.sum", func(t *testing.T) {
		tmpDir := t.TempDir()

		deps := []parser.Dependency{
			{Name: "github.com/gin-gonic/gin", Version: "1.9.0", Ecosystem: "Go"},
		}

		results := VerifyIntegrity(deps, tmpDir, DefaultConfig())

		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}

		if results[0].Status != StatusMissing {
			t.Errorf("expected MISSING status, got %s", results[0].Status)
		}
	})

	t.Run("go modules with valid go.sum", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a go.sum with a known entry
		goSumContent := "github.com/gin-gonic/gin@v1.9.0 h1:tVPs6Tn1yGm6nKTrsS5KxPcYxG/VMqAIb6R0gxp8j0=\n"
		if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(goSumContent), 0644); err != nil {
			t.Fatal(err)
		}

		deps := []parser.Dependency{
			{Name: "github.com/gin-gonic/gin", Version: "1.9.0", Ecosystem: "Go"},
		}

		results := VerifyIntegrity(deps, tmpDir, DefaultConfig())

		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}

		if results[0].Status != StatusOK {
			t.Errorf("expected OK status, got %s: %s", results[0].Status, results[0].Error)
		}
	})

	t.Run("npm missing lockfile", func(t *testing.T) {
		tmpDir := t.TempDir()

		deps := []parser.Dependency{
			{Name: "express", Version: "4.18.0", Ecosystem: "npm"},
		}

		results := VerifyIntegrity(deps, tmpDir, DefaultConfig())

		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}

		if results[0].Status != StatusMissing {
			t.Errorf("expected MISSING status, got %s", results[0].Status)
		}
	})

	t.Run("filterByEcosystem", func(t *testing.T) {
		deps := []parser.Dependency{
			{Name: "gin", Version: "1.0", Ecosystem: "Go"},
			{Name: "express", Version: "4.0", Ecosystem: "npm"},
			{Name: "chi", Version: "5.0", Ecosystem: "Go"},
		}

		goDeps := filterByEcosystem(deps, "Go")
		if len(goDeps) != 2 {
			t.Errorf("expected 2 Go deps, got %d", len(goDeps))
		}

		npmDeps := filterByEcosystem(deps, "npm")
		if len(npmDeps) != 1 {
			t.Errorf("expected 1 npm dep, got %d", len(npmDeps))
		}
	})
}

func TestParseGoSum(t *testing.T) {
	t.Run("parses valid go.sum", func(t *testing.T) {
		tmpDir := t.TempDir()
		content := "github.com/gin-gonic/gin@v1.9.0 h1:tVPs6Tn1yGm6nKTrsS5KxPcYxG/VMqAIb6R0gxp8j0=\n" +
			"github.com/go-chi/chi/v5@v5.0.0 h1:jp2HWENsg3iI43s9+fQY0fz2Fy5Bz8PkMSMfNCrBE8I=\n"

		goSumPath := filepath.Join(tmpDir, "go.sum")
		if err := os.WriteFile(goSumPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		entries, err := parseGoSum(tmpDir)
		if err != nil {
			t.Fatalf("parseGoSum failed: %v", err)
		}

		if len(entries) != 2 {
			t.Errorf("expected 2 entries, got %d", len(entries))
		}

		hashes, ok := entries["github.com/gin-gonic/gin@v1.9.0"]
		if !ok {
			t.Error("missing gin entry")
		}
		if len(hashes) != 1 {
			t.Errorf("expected 1 hash, got %d", len(hashes))
		}
	})

	t.Run("missing go.sum returns error", func(t *testing.T) {
		_, err := parseGoSum("/nonexistent")
		if err == nil {
			t.Error("expected error for missing go.sum")
		}
	})
}
