package typosquat

// levenshtein computes the edit distance between two strings using
// the Wagner-Fischer algorithm. O(m*n) time and space.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			delCost := prev[j] + 1
			insCost := curr[j-1] + 1
			subCost := prev[j-1] + cost
			curr[j] = minInt(delCost, minInt(insCost, subCost))
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

// LevenshteinRatio returns normalized Levenshtein similarity (0.0-1.0).
func LevenshteinRatio(a, b string) float64 {
	maxLen := maxInt(len(a), len(b))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(levenshtein(a, b))/float64(maxLen)
}

// jaroWinkler computes Jaro-Winkler similarity between two strings.
// Gives higher weight to matching prefixes, which is common in package names.
func jaroWinkler(a, b string) float64 {
	la, lb := len(a), len(b)

	if la == 0 && lb == 0 {
		return 1.0
	}
	if la == 0 || lb == 0 {
		return 0.0
	}

	matchDist := maxInt(la, lb)/2 - 1
	if matchDist < 0 {
		matchDist = 0
	}

	matchedA := make([]bool, la)
	matchedB := make([]bool, lb)

	var matches, transpositions int

	for i := 0; i < la; i++ {
		start := i - matchDist
		if start < 0 {
			start = 0
		}
		end := i + matchDist + 1
		if end > lb {
			end = lb
		}

		for j := start; j < end; j++ {
			if matchedB[j] || a[i] != b[j] {
				continue
			}
			matchedA[i] = true
			matchedB[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0.0
	}

	k := 0
	for i := 0; i < la; i++ {
		if !matchedA[i] {
			continue
		}
		for !matchedB[k] {
			k++
		}
		if a[i] != b[k] {
			transpositions++
		}
		k++
	}

	jaro := (float64(matches)/float64(la) +
		float64(matches)/float64(lb) +
		float64(matches-transpositions/2)/float64(matches)) / 3.0

	prefixLen := 0
	maxPrefix := minInt(4, minInt(la, lb))
	for i := 0; i < maxPrefix; i++ {
		if a[i] == b[i] {
			prefixLen++
		} else {
			break
		}
	}

	return jaro + float64(prefixLen)*0.1*(1.0-jaro)
}

// JaroWinkler returns Jaro-Winkler similarity (0.0-1.0).
func JaroWinkler(a, b string) float64 {
	return jaroWinkler(a, b)
}

// diceCoefficient computes Sorensen-Dice coefficient using bigrams.
func diceCoefficient(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) < 2 || len(b) < 2 {
		return 0.0
	}

	bigramsA := make(map[string]int, len(a)-1)
	for i := 0; i < len(a)-1; i++ {
		bigramsA[a[i:i+2]]++
	}

	bigramsB := make(map[string]int, len(b)-1)
	for i := 0; i < len(b)-1; i++ {
		bigramsB[b[i:i+2]]++
	}

	var intersection int
	for bg, countA := range bigramsA {
		if countB, ok := bigramsB[bg]; ok {
			intersection += minInt(countA, countB)
		}
	}

	total := (len(a) - 1) + (len(b) - 1)
	if total == 0 {
		return 0.0
	}

	return 2.0 * float64(intersection) / float64(total)
}

// DiceCoefficient returns bigram Dice coefficient (0.0-1.0).
func DiceCoefficient(a, b string) float64 {
	return diceCoefficient(a, b)
}

// CombinedSimilarity returns a weighted similarity score (0.0-1.0).
// Weights: 40% Levenshtein + 30% Jaro-Winkler + 30% Dice.
func CombinedSimilarity(a, b string) float64 {
	la := LevenshteinRatio(a, b)
	jw := JaroWinkler(a, b)
	dc := DiceCoefficient(a, b)
	return 0.4*la + 0.3*jw + 0.3*dc
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}


