package typosquat

// homoglyphMap defines characters that are commonly confused in typosquatting attacks.
// Attackers replace these to create visually similar package names.
var homoglyphMap = map[rune]rune{
	'o': '0',
	'l': '1',
	'i': '1',
	's': '5',
	'a': '4',
	'e': '3',
	'b': '8',
	'g': '9',
}

// vowels are used for vowel-swap mutations.
var vowels = []rune{'a', 'e', 'i', 'o', 'u'}

// commonAffixes are appended/prepended to create "official-looking" variants.
// Attackers use these to make packages look like official tooling or scoped packages.
var commonAffixes = []string{
	"-cli", "-core", "-utils", "-tools", "-js", "-api",
	"-app", "-lib", "-sdk", "-plugin", "-ext", "-helper",
}

// Mutation represents a single typosquat variant of a package name.
type Mutation struct {
	Original  string
	Mutated   string
	Technique string
}

// GenerateMutations produces all possible typosquat mutations of a package name.
// Each technique models a different attack vector used by malicious actors.
func GenerateMutations(name string) []Mutation {
	// Pre-allocate with a rough estimate to reduce reallocations.
	results := make([]Mutation, 0, len(name)*2+4*len(commonAffixes))

	results = append(results, deletionMutations(name)...)
	results = append(results, swapMutations(name)...)
	results = append(results, homoglyphMutations(name)...)
	results = append(results, vowelSwapMutations(name)...)
	results = append(results, affixMutations(name)...)

	return results
}

// deletionMutations removes one character at each position.
// Models the "fat-finger" scenario where a user misses a character.
func deletionMutations(name string) []Mutation {
	runes := []rune(name)
	results := make([]Mutation, 0, len(runes))

	for i := 0; i < len(runes); i++ {
		mutated := string(append(runes[:i:i], runes[i+1:]...))
		if mutated != name {
			results = append(results, Mutation{
				Original:  name,
				Mutated:   mutated,
				Technique: "deletion",
			})
		}
	}

	return results
}

// swapMutations swaps each adjacent pair of characters.
// Models transposition errors common in typing.
func swapMutations(name string) []Mutation {
	runes := []rune(name)
	if len(runes) < 2 {
		return nil
	}
	results := make([]Mutation, 0, len(runes)-1)

	for i := 0; i < len(runes)-1; i++ {
		swapped := append([]rune(nil), runes...)
		swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
		mutated := string(swapped)
		if mutated != name {
			results = append(results, Mutation{
				Original:  name,
				Mutated:   mutated,
				Technique: "swap",
			})
		}
	}

	return results
}

// homoglyphMutations replaces characters with visually similar lookalikes.
// This is the most common typosquatting technique in package registries.
func homoglyphMutations(name string) []Mutation {
	runes := []rune(name)
	results := make([]Mutation, 0, len(runes))

	for i, r := range runes {
		replacement, ok := homoglyphMap[r]
		if !ok {
			continue
		}
		mutated := string(append(append(runes[:i:i], replacement), runes[i+1:]...))
		if mutated != name {
			results = append(results, Mutation{
				Original:  name,
				Mutated:   mutated,
				Technique: "homoglyph",
			})
		}
	}

	return results
}

// vowelSwapMutations replaces each vowel with every other vowel.
// Explores phonetic confusion in package names.
func vowelSwapMutations(name string) []Mutation {
	runes := []rune(name)
	results := make([]Mutation, 0, len(runes)*len(vowels))

	for i, r := range runes {
		if !isVowel(r) {
			continue
		}
		for _, v := range vowels {
			if v == r {
				continue
			}
			mutated := string(append(append(runes[:i:i], v), runes[i+1:]...))
			results = append(results, Mutation{
				Original:  name,
				Mutated:   mutated,
				Technique: "vowel-swap",
			})
		}
	}

	return results
}

// affixMutations appends common affixes to create "official-looking" variants.
// Also prepends affixes to mimic namespace conventions like @org/package in npm.
func affixMutations(name string) []Mutation {
	results := make([]Mutation, 0, 2*len(commonAffixes))

	for _, affix := range commonAffixes {
		// Suffix variant: name + affix
		results = append(results, Mutation{
			Original:  name,
			Mutated:   name + affix,
			Technique: "suffix",
		})
		// Prefix variant: affix + name
		results = append(results, Mutation{
			Original:  name,
			Mutated:   affix + name,
			Technique: "prefix",
		})
	}

	return results
}

// isVowel checks if a rune is a lowercase vowel.
func isVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}
