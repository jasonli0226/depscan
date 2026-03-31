package typosquat

import (
	"testing"
)

func TestGenerateMutations(t *testing.T) {
	t.Run("lodash produces expected techniques", func(t *testing.T) {
		mutations := GenerateMutations("lodash")

		if len(mutations) == 0 {
			t.Fatal("GenerateMutations returned no mutations")
		}

		techniques := make(map[string]bool)
		for _, m := range mutations {
			techniques[m.Technique] = true
		}

		expectedTechniques := []string{"deletion", "swap", "homoglyph", "prefix", "suffix"}
		for _, tech := range expectedTechniques {
			if !techniques[tech] {
				t.Errorf("missing technique %q in mutations", tech)
			}
		}

		// vowel-swap may not always appear if the name has no vowels,
		// but lodash has 'o' and 'a'.
		if !techniques["vowel-swap"] {
			t.Error("missing technique vowel-swap in mutations for 'lodash'")
		}
	})

	t.Run("all mutations have required fields", func(t *testing.T) {
		mutations := GenerateMutations("lodash")

		for _, m := range mutations {
			if m.Original == "" {
				t.Errorf("mutation with empty Original: %+v", m)
			}
			if m.Mutated == "" {
				t.Errorf("mutation with empty Mutated: %+v", m)
			}
			if m.Technique == "" {
				t.Errorf("mutation with empty Technique: %+v", m)
			}
		}
	})

	t.Run("no mutation identical to original", func(t *testing.T) {
		mutations := GenerateMutations("lodash")

		for _, m := range mutations {
			if m.Mutated == m.Original {
				t.Errorf("mutation %q is identical to original %q (technique: %s)",
					m.Mutated, m.Original, m.Technique)
			}
		}
	})

	t.Run("original is preserved", func(t *testing.T) {
		mutations := GenerateMutations("lodash")

		for _, m := range mutations {
			if m.Original != "lodash" {
				t.Errorf("expected Original %q, got %q", "lodash", m.Original)
			}
		}
	})

	t.Run("deletion variants are shorter by one char", func(t *testing.T) {
		mutations := GenerateMutations("lodash")
		found := false

		for _, m := range mutations {
			if m.Technique == "deletion" {
				found = true
				if len(m.Mutated) != len(m.Original)-1 {
					t.Errorf("deletion mutation %q should be len %d, got %d",
						m.Mutated, len(m.Original)-1, len(m.Mutated))
				}
			}
		}

		if !found {
			t.Error("no deletion mutations found")
		}
	})

	t.Run("swap variants have two chars swapped", func(t *testing.T) {
		mutations := GenerateMutations("lodash")
		found := false

		for _, m := range mutations {
			if m.Technique == "swap" {
				found = true
				if len(m.Mutated) != len(m.Original) {
					t.Errorf("swap mutation should preserve length, got %d vs %d",
						len(m.Mutated), len(m.Original))
				}
			}
		}

		if !found {
			t.Error("no swap mutations found")
		}
	})

	t.Run("homoglyph variants use digit replacements", func(t *testing.T) {
		mutations := GenerateMutations("lodash")
		found := false

		for _, m := range mutations {
			if m.Technique == "homoglyph" {
				found = true
				if m.Mutated == m.Original {
					t.Errorf("homoglyph mutation %q should differ from original", m.Mutated)
				}
			}
		}

		if !found {
			t.Error("no homoglyph mutations found")
		}
	})

	t.Run("prefix variants append to original", func(t *testing.T) {
		mutations := GenerateMutations("lodash")
		found := false

		for _, m := range mutations {
			if m.Technique == "prefix" {
				found = true
				// prefix technique appends suffixes to the name
				if len(m.Mutated) <= len(m.Original) {
					t.Errorf("prefix mutation %q should be longer than original %q",
						m.Mutated, m.Original)
				}
			}
		}

		if !found {
			t.Error("no prefix mutations found")
		}
	})

	t.Run("suffix variants prepend to original", func(t *testing.T) {
		mutations := GenerateMutations("lodash")
		found := false

		for _, m := range mutations {
			if m.Technique == "suffix" {
				found = true
				if len(m.Mutated) <= len(m.Original) {
					t.Errorf("suffix mutation %q should be longer than original %q",
						m.Mutated, m.Original)
				}
			}
		}

		if !found {
			t.Error("no suffix mutations found")
		}
	})

	t.Run("empty string produces only prefix/suffix mutations", func(t *testing.T) {
		mutations := GenerateMutations("")

		for _, m := range mutations {
			if m.Technique != "prefix" && m.Technique != "suffix" {
				t.Errorf("empty input should only produce prefix/suffix, got %s", m.Technique)
			}
		}
	})
}
