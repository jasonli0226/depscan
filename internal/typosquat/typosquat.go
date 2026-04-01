package typosquat

import (
	"sort"
	"strings"
	"sync"

	"github.com/jasonli0226/depscan/internal/parser"
)

// Package-level cache for mutation maps, built once per process.
var (
	cachedGoMutMap  map[string]mutationInfo
	cachedNpmMutMap map[string]mutationInfo
	mutMapsOnce     sync.Once
)

func initMutationMaps(goPkgs, npmPkgs []string) {
	cachedGoMutMap = buildMutationMap(goPkgs)
	cachedNpmMutMap = buildMutationMap(npmPkgs)
}

// TyposquatResult identifies a dependency that closely resembles a popular package.
type TyposquatResult struct {
	Package      parser.Dependency
	ConfusedWith string  // the popular package it mimics
	Similarity   float64 // 0.0-1.0
	Technique    string  // "homoglyph", "transposition", "deletion", "direct-similarity", etc.
}

// Config controls the behavior of typosquat detection.
type Config struct {
	Threshold float64 // minimum similarity to flag (default 0.75)
	Enabled   bool
}

// DefaultConfig returns the recommended default settings.
func DefaultConfig() Config {
	return Config{
		Threshold: 0.75,
		Enabled:   true,
	}
}

// CheckTyposquat scans a list of dependencies for potential typosquat attacks
// by comparing each against known popular packages using similarity metrics
// and mutation analysis.
func CheckTyposquat(deps []parser.Dependency, cfg Config) []TyposquatResult {
	if !cfg.Enabled {
		return nil
	}

	if cfg.Threshold == 0 {
		cfg.Threshold = 0.75
	}

	popular, err := EnsurePopularPackages()
	if err != nil {
		// If we cannot load any reference data, skip detection rather than failing.
		return nil
	}

	// Build ecosystem-specific reference sets.
	goRefs := buildSet(popular.GoModules)
	npmRefs := buildSet(popular.NpmPackages)

	// Build mutation maps once per process via sync.Once.
	mutMapsOnce.Do(func() {
		initMutationMaps(popular.GoModules, popular.NpmPackages)
	})

	results := make([]TyposquatResult, 0)

	for _, dep := range deps {
		depName := strings.ToLower(dep.Name)

		var refs map[string]bool
		var mutMap map[string]mutationInfo

		switch strings.ToLower(dep.Ecosystem) {
		case "go":
			refs = goRefs
			mutMap = cachedGoMutMap
		case "npm":
			refs = npmRefs
			mutMap = cachedNpmMutMap
		default:
			// Unknown ecosystem: check against all reference sets.
			refs = mergeSets(goRefs, npmRefs)
			mutMap = mergeMutationMaps(cachedGoMutMap, cachedNpmMutMap)
		}

		depResults := checkDependency(dep, depName, refs, mutMap, cfg.Threshold)
		results = append(results, depResults...)
	}

	return dedupAndSort(results)
}

// mutationInfo pairs a popular package name with the mutation technique that produced a variant.
type mutationInfo struct {
	original  string
	technique string
}

// checkDependency runs similarity and mutation checks for a single dependency
// against the reference set.
func checkDependency(dep parser.Dependency, depName string, refs map[string]bool, mutMap map[string]mutationInfo, threshold float64) []TyposquatResult {
	results := make([]TyposquatResult, 0)
	seen := make(map[string]bool)

	// Phase 1: Direct similarity comparison against all popular packages.
	// Skip exact matches (a package matching itself is not a typosquat).
	for popularPkg := range refs {
		if depName == strings.ToLower(popularPkg) {
			continue
		}
		popularLower := strings.ToLower(popularPkg)
		sim := CombinedSimilarity(depName, popularLower)

		if sim >= threshold && !seen[popularPkg] {
			seen[popularPkg] = true
			results = append(results, TyposquatResult{
				Package:      dep,
				ConfusedWith: popularPkg,
				Similarity:   sim,
				Technique:    "direct-similarity",
			})
		}
	}

	// Phase 2: Check if the dependency name matches any mutation of a popular package.
	// This catches cases where similarity metrics alone miss the attack.
	if info, ok := mutMap[depName]; ok && !seen[info.original] {
		results = append(results, TyposquatResult{
			Package:      dep,
			ConfusedWith: info.original,
			Similarity:   1.0, // exact mutation match
			Technique:    info.technique,
		})
	}

	return results
}

// buildMutationMap generates all mutations for each popular package and builds
// a reverse lookup: mutated name -> original name + technique.
func buildMutationMap(packages []string) map[string]mutationInfo {
	m := make(map[string]mutationInfo)

	for _, pkg := range packages {
		pkgLower := strings.ToLower(pkg)
		mutations := GenerateMutations(pkgLower)

		for _, mut := range mutations {
			if _, exists := m[mut.Mutated]; !exists {
				m[mut.Mutated] = mutationInfo{
					original:  pkg,
					technique: mut.Technique,
				}
			}
		}
	}

	return m
}

// buildSet creates a lookup set from a string slice.
func buildSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[strings.ToLower(item)] = true
	}
	return s
}

// mergeSets combines two sets into one.
func mergeSets(a, b map[string]bool) map[string]bool {
	merged := make(map[string]bool, len(a)+len(b))
	for k := range a {
		merged[k] = true
	}
	for k := range b {
		merged[k] = true
	}
	return merged
}

// mergeMutationMaps combines two mutation maps. First map wins on conflicts.
func mergeMutationMaps(a, b map[string]mutationInfo) map[string]mutationInfo {
	merged := make(map[string]mutationInfo, len(a)+len(b))
	for k, v := range a {
		merged[k] = v
	}
	for k, v := range b {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}
	return merged
}

// dedupAndSort removes duplicate results (same package + confusedWith) and
// sorts by similarity descending.
func dedupAndSort(results []TyposquatResult) []TyposquatResult {
	if len(results) == 0 {
		return results
	}

	seen := make(map[string]bool, len(results))
	unique := make([]TyposquatResult, 0, len(results))

	for _, r := range results {
		key := r.Package.Name + "|" + r.ConfusedWith
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, r)
	}

	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Similarity > unique[j].Similarity
	})

	return unique
}
