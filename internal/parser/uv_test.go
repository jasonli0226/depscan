package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseUVPackages(t *testing.T) {
	t.Run("parses valid uv.lock", func(t *testing.T) {
		tmpDir := t.TempDir()

		content := `
version = 1

[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.1.0"
`
		if err := os.WriteFile(filepath.Join(tmpDir, "uv.lock"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		deps, err := ParseUVPackages(tmpDir)
		if err != nil {
			t.Fatalf("ParseUVPackages failed: %v", err)
		}

		if len(deps) != 2 {
			t.Errorf("expected 2 deps, got %d", len(deps))
		}

		if deps[0].Name != "requests" {
			t.Errorf("expected name 'requests', got %s", deps[0].Name)
		}
		if deps[0].Version != "2.31.0" {
			t.Errorf("expected version '2.31.0', got %s", deps[0].Version)
		}
		if deps[0].Ecosystem != "PyPI" {
			t.Errorf("expected ecosystem 'PyPI', got %s", deps[0].Ecosystem)
		}
	})

	t.Run("handles missing uv.lock", func(t *testing.T) {
		_, err := ParseUVPackages("/nonexistent")
		if err == nil {
			t.Error("expected error for missing uv.lock")
		}
	})

	t.Run("handles invalid TOML", func(t *testing.T) {
		tmpDir := t.TempDir()

		content := `invalid toml [[[[`
		if err := os.WriteFile(filepath.Join(tmpDir, "uv.lock"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := ParseUVPackages(tmpDir)
		if err == nil {
			t.Error("expected error for invalid TOML")
		}
	})

	t.Run("deduplicates packages", func(t *testing.T) {
		tmpDir := t.TempDir()

		content := `
version = 1

[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "requests"
version = "2.31.0"
`
		if err := os.WriteFile(filepath.Join(tmpDir, "uv.lock"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		deps, err := ParseUVPackages(tmpDir)
		if err != nil {
			t.Fatalf("ParseUVPackages failed: %v", err)
		}

		if len(deps) != 1 {
			t.Errorf("expected 1 dep after deduplication, got %d", len(deps))
		}
	})

	t.Run("skips packages with missing fields", func(t *testing.T) {
		tmpDir := t.TempDir()

		content := `
version = 1

[[package]]
name = "valid-package"
version = "1.0.0"

[[package]]
name = "missing-version"

[[package]]
version = "1.0.0"
`
		if err := os.WriteFile(filepath.Join(tmpDir, "uv.lock"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		deps, err := ParseUVPackages(tmpDir)
		if err != nil {
			t.Fatalf("ParseUVPackages failed: %v", err)
		}

		if len(deps) != 1 {
			t.Errorf("expected 1 valid dep, got %d", len(deps))
		}
	})

	t.Run("handles empty file", func(t *testing.T) {
		tmpDir := t.TempDir()

		if err := os.WriteFile(filepath.Join(tmpDir, "uv.lock"), []byte(""), 0644); err != nil {
			t.Fatal(err)
		}

		deps, err := ParseUVPackages(tmpDir)
		if err != nil {
			t.Fatalf("ParseUVPackages failed: %v", err)
		}

		if len(deps) != 0 {
			t.Errorf("expected 0 deps for empty file, got %d", len(deps))
		}
	})

	t.Run("normalizes versions with v prefix", func(t *testing.T) {
		tmpDir := t.TempDir()

		content := `
version = 1

[[package]]
name = "test-package"
version = "v1.2.3"
`
		if err := os.WriteFile(filepath.Join(tmpDir, "uv.lock"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		deps, err := ParseUVPackages(tmpDir)
		if err != nil {
			t.Fatalf("ParseUVPackages failed: %v", err)
		}

		if len(deps) != 1 {
			t.Fatalf("expected 1 dep, got %d", len(deps))
		}

		if deps[0].Version != "1.2.3" {
			t.Errorf("expected version '1.2.3', got %s", deps[0].Version)
		}
	})
}

func TestIsValidUVPackage(t *testing.T) {
	tests := []struct {
		name     string
		pkg      UVPackage
		expected bool
	}{
		{
			name:     "valid package",
			pkg:      UVPackage{Name: "requests", Version: "2.31.0"},
			expected: true,
		},
		{
			name:     "missing name",
			pkg:      UVPackage{Name: "", Version: "2.31.0"},
			expected: false,
		},
		{
			name:     "missing version",
			pkg:      UVPackage{Name: "requests", Version: ""},
			expected: false,
		},
		{
			name:     "both missing",
			pkg:      UVPackage{Name: "", Version: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidUVPackage(tt.pkg); got != tt.expected {
				t.Errorf("isValidUVPackage() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version with v prefix",
			version:  "v1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "version without v prefix",
			version:  "1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "version with leading/trailing spaces",
			version:  " 1.2.3 ",
			expected: "1.2.3",
		},
		{
			name:     "version with v and spaces",
			version:  " v1.2.3 ",
			expected: "1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeVersion(tt.version); got != tt.expected {
				t.Errorf("normalizeVersion() = %v, want %v", got, tt.expected)
			}
		})
	}
}
