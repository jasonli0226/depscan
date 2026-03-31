package typosquat

import (
	"math"
	"testing"
)

func TestLevenshteinRatio(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want float64
	}{
		{"identical", "abc", "abc", 1.0},
		{"completely different", "abc", "xyz", 0.0},
		{"one diff", "abc", "abd", 0.667},
		{"empty both", "", "", 1.0},
		{"one empty", "", "abc", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LevenshteinRatio(tt.a, tt.b)
			if math.Abs(got-tt.want) > 0.01 {
				t.Errorf("LevenshteinRatio(%q, %q) = %.3f, want %.3f", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestJaroWinkler(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		min  float64
		max  float64
	}{
		{"identical", "express", "express", 1.0, 1.0},
		{"similar", "crate", "trace", 0.7, 0.85},
		{"prefix match", "express", "expressjs", 0.8, 1.0},
		{"empty", "", "", 1.0, 1.0},
		{"one empty", "abc", "", 0.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JaroWinkler(tt.a, tt.b)
			if got < tt.min || got > tt.max {
				t.Errorf("JaroWinkler(%q, %q) = %.3f, want [%.3f, %.3f]", tt.a, tt.b, got, tt.min, tt.max)
			}
		})
	}
}

func TestDiceCoefficient(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		min  float64
		max  float64
	}{
		{"identical", "react", "react", 1.0, 1.0},
		{"similar", "night", "nacht", 0.2, 0.3},
		{"completely different", "abc", "xyz", 0.0, 0.1},
		{"short strings", "a", "b", 0.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiceCoefficient(tt.a, tt.b)
			if got < tt.min || got > tt.max {
				t.Errorf("DiceCoefficient(%q, %q) = %.3f, want [%.3f, %.3f]", tt.a, tt.b, got, tt.min, tt.max)
			}
		})
	}
}

func TestCombinedSimilarity(t *testing.T) {
	tests := []struct {
		name      string
		a         string
		b         string
		minThresh float64
		maxThresh float64
	}{
		{"identical", "express", "express", 0.99, 1.0},
		{"typosquat lodash", "lodash", "lodahs", 0.7, 1.0},
		{"different", "react", "vue", 0.0, 0.5},
		{"homoglyph", "request", "requ3st", 0.7, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CombinedSimilarity(tt.a, tt.b)
			if got < tt.minThresh || got > tt.maxThresh {
				t.Errorf("CombinedSimilarity(%q, %q) = %.3f, want [%.3f, %.3f]", tt.a, tt.b, got, tt.minThresh, tt.maxThresh)
			}
		})
	}
}
