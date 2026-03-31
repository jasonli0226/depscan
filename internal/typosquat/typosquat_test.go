package typosquat

import (
	"testing"

	"github.com/jasonli0226/depscan/internal/parser"
)

func TestCheckTyposquat(t *testing.T) {
	t.Run("detects typosquat via mutation (Go module)", func(t *testing.T) {
		// "lodahs" is a swap mutation of "lodash" which is in the curated npm list.
		// But since npm fetch may fail, test with a Go module that's definitely in our list.
		// "gin-gonic/gin" -> swap mutation "gni-gonic/gin"
		deps := []parser.Dependency{
			{Name: "gni-gonic/gin", Version: "1.0.0", Ecosystem: "Go"},
		}

		cfg := Config{Threshold: 0.01, Enabled: true}
		results := CheckTyposquat(deps, cfg)

		if len(results) == 0 {
			// Debug: check if popular packages loaded
			popular, err := EnsurePopularPackages()
			if err != nil {
				t.Fatalf("failed to load popular packages: %v", err)
			}
			t.Logf("Go modules loaded: %d, npm packages loaded: %d",
				len(popular.GoModules), len(popular.NpmPackages))
			t.Fatal("expected to flag gni-gonic/gin as typosquat of gin-gonic/gin")
		}

		found := false
		for _, r := range results {
			if r.ConfusedWith == "github.com/gin-gonic/gin" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected match with github.com/gin-gonic/gin, got %d results", len(results))
		}
	})

	t.Run("detects typosquat via similarity", func(t *testing.T) {
		deps := []parser.Dependency{
			{Name: "gin-gonic/gin", Version: "1.0.0", Ecosystem: "Go"},
		}

		// Very low threshold to catch any similarity
		cfg := Config{Threshold: 0.5, Enabled: true}
		results := CheckTyposquat(deps, cfg)

		found := false
		for _, r := range results {
			if r.ConfusedWith == "github.com/gin-gonic/gin" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected gin-gonic/gin matched with github.com/gin-gonic/gin, got %d results", len(results))
		}
	})

	t.Run("returns empty for disabled check", func(t *testing.T) {
		deps := []parser.Dependency{
			{Name: "lodahs", Version: "1.0.0", Ecosystem: "npm"},
		}

		cfg := Config{Threshold: 0.75, Enabled: false}
		results := CheckTyposquat(deps, cfg)

		if len(results) != 0 {
			t.Errorf("expected 0 results when disabled, got %d", len(results))
		}
	})

	t.Run("returns empty for empty deps", func(t *testing.T) {
		results := CheckTyposquat(nil, DefaultConfig())
		if len(results) != 0 {
			t.Errorf("expected 0 results for empty deps, got %d", len(results))
		}
	})

	t.Run("results sorted by similarity descending", func(t *testing.T) {
		deps := []parser.Dependency{
			{Name: "gin-gonic/gin", Version: "1.0.0", Ecosystem: "Go"},
			{Name: "go-chi/chj", Version: "1.0.0", Ecosystem: "Go"},
		}

		cfg := Config{Threshold: 0.5, Enabled: true}
		results := CheckTyposquat(deps, cfg)

		if len(results) < 2 {
			t.Skip("not enough results to check sorting")
		}

		for i := 1; i < len(results); i++ {
			if results[i].Similarity > results[i-1].Similarity {
				t.Errorf("results not sorted: [%d]=%.3f > [%d]=%.3f",
					i, results[i].Similarity, i-1, results[i-1].Similarity)
			}
		}
	})

	t.Run("no duplicates in results", func(t *testing.T) {
		deps := []parser.Dependency{
			{Name: "gin-gonic/gin", Version: "1.0.0", Ecosystem: "Go"},
		}

		cfg := Config{Threshold: 0.5, Enabled: true}
		results := CheckTyposquat(deps, cfg)

		seen := make(map[string]bool)
		for _, r := range results {
			key := r.Package.Name + ":" + r.ConfusedWith
			if seen[key] {
				t.Errorf("duplicate result: %s", key)
			}
			seen[key] = true
		}
	})
}
