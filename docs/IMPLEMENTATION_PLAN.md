# Implementation Plan: Typosquat Detection + Dependency Integrity

> Branch: `feat/typosquat-and-integrity`
> Base: `main` (b9e0db4)

## Current State

depscan scans Go/npm/pnpm dependencies against OSV.dev for known CVEs. It has:
- Parsers: `internal/parser/` (go.go, npm.go, pnpm.go)
- Scanner: `internal/scanner/osv.go` (OSV.dev API queries)
- Scorer: `internal/scorer/risk.go` (risk 0-100)
- Output: `internal/output/` (terminal.go, json.go)

**Known issue**: `main.go` imports `cmd/depscan` package that doesn't exist in the repo. This must be fixed first.

**Architecture**: Each scanner is standalone — takes `[]parser.Dependency`, returns results. This is the pattern we follow.

---

## Phase 0: Fix Missing cmd Package

### Problem
`main.go` imports `github.com/jasonli0226/depscan/cmd/depscan` but no `cmd/` directory exists. The tool cannot build.

### Tasks
- [ ] Create `cmd/depscan/root.go` with Cobra root command
- [ ] Create `cmd/depscan/scan.go` with scan subcommand
- [ ] Wire up: parse deps → scan OSV → score → output
- [ ] Add `--output/-o` flag for JSON export
- [ ] Add `--version` flag
- [ ] Verify `make build` works

### Files
```
cmd/depscan/root.go    # Cobra root + version
cmd/depscan/scan.go    # scan subcommand, orchestrates the pipeline
```

### Acceptance
- `make build` succeeds
- `./depscan ./some-project` runs a full scan
- `./depscan -o report.json ./some-project` writes JSON

---

## Phase 1: Typosquat Detection

### Overview
Flag packages whose names are suspiciously similar to popular packages in the same ecosystem. This catches supply chain attacks where attackers publish malicious packages with names like `lod-ash` instead of `lodash`.

### Approach

#### 1a. String Similarity Engine (`internal/typosquat/similarity.go`)

Implement a `Similarity(pkg1, pkg2 string) float64` function that combines multiple algorithms:

| Algorithm | Weight | Why |
|-----------|--------|-----|
| Levenshtein distance (normalized) | 40% | Catches character-level typos |
| Jaro-Winkler | 30% | Good for prefix-heavy matches (common in package names) |
| Dice coefficient (bigram) | 30% | Catches reordered/inserted chars |

**Threshold**: similarity >= 0.75 = flag as suspicious.

**Implementation**: No external dependency — implement Levenshtein + Jaro-Winkler + Dice from scratch. These are well-known algorithms, ~30 lines each. Keeps depscan dependency-free for core logic.

#### 1b. Mutation Generator (`internal/typosquat/mutations.go`)

Generate common typosquatting mutations of a package name:

```
Input: "lodash"
Mutations:
  - Character removal: "odahs", "lodahs", "lodsh"
  - Adjacent swap: "oldash", "ldoash"
  - Homoglyph: "l0dash" (o→0), "1odash" (l→1)
  - Vowel swap: "ladash", "ledash", "lidash", "lodish", "lodush"
  - Dot confusion: "lodash.utils" (adds fake subpackage)
  - Prefix/suffix: "lodash-cli", "lodash-core", "lodash-tools"
```

Check if any mutation matches a real package in the dependency list.

#### 1c. Popular Package Database (`internal/typosquat/popular.go`)

Need a baseline of "popular" packages to compare against.

**Go modules**: Use Go module proxy `proxy.golang.org` — the `@v/list` endpoint gives all known module versions. Cross-reference with download counts (not directly available, but we can use GitHub stars as proxy, or maintain a curated list of top 500 Go modules).

**npm packages**: Use npm registry API `https://registry.npmjs.org/-/v1/search` with `?size=1000&sort=popularity`. This gives download counts. Cache top 1000 packages.

**Strategy**: 
1. On first run, fetch and cache popular packages for each ecosystem
2. Store cache in `~/.depscan/cache/typosquat/` as JSON
3. Refresh cache every 7 days (configurable)
4. If offline, use cached data (or skip typosquat check)

#### 1d. Scanner Integration (`internal/typosquat/typosquat.go`)

```go
type TyposquatResult struct {
    Package     parser.Dependency
    ConfusedWith string      // the popular package it mimics
    Similarity  float64      // 0.0-1.0
    Technique   string       // "homoglyph", "transposition", etc.
}
```

`func CheckTyposquat(deps []parser.Dependency) []TyposquatResult`

For each dependency:
1. Compare against all popular packages in the same ecosystem
2. If similarity >= threshold, flag it
3. Also generate mutations and check against dependency list itself (catches in-project confusion)

#### 1e. CLI Integration

- New flag: `--typosquat` (enabled by default)
- New flag: `--typosquat-threshold` (default 0.75)
- Terminal output shows typosquat warnings in yellow
- JSON output includes `typosquat_warnings` array
- Risk score: each typosquat hit adds 15 points (HIGH severity equivalent)

### Files
```
internal/typosquat/similarity.go    # Levenshtein, Jaro-Winkler, Dice
internal/typosquat/mutations.go     # Generate common typosquat mutations
internal/typosquat/popular.go       # Fetch & cache popular package lists
internal/typosquat/typosquat.go     # Main CheckTyposquat function
```

### Tests
```
internal/typosquat/similarity_test.go    # Test algorithms with known pairs
internal/typosquat/mutations_test.go     # Verify mutation generation
internal/typosquat/typosquat_test.go     # End-to-end with mock data
```

### Acceptance
- `depscan --typosquat ./project` flags known typosquat patterns
- Popular package cache persists across runs
- Offline mode works with cached data
- No false positives on standard library packages

---

## Phase 2: Dependency Integrity Verification

### Overview
Verify that dependency checksums in lockfiles match what the package registry expects. Detect tampered lockfiles or compromised packages.

### Approach

#### 2a. Go Module Integrity (`internal/integrity/gomod.go`)

**How it works**: 
- `go.sum` contains `<module>@<version> <hash1> <hash2>` entries
- The Go checksum database (`sum.golang.org`) holds the canonical hashes
- Use `golang.org/x/mod/sumdb` package to verify against the database

**Implementation**:
1. Parse `go.sum` to extract all module@version + hash pairs
2. For each entry, query `sum.golang.org/lookup/<module>@<version>`
3. Compare returned hashes with `go.sum` entries
4. Flag mismatches as integrity failures

**Package**: `golang.org/x/mod/sumdb` — official Go module, well-maintained.

```go
type IntegrityResult struct {
    Package   parser.Dependency
    Expected  string   // hash from registry
    Actual    string   // hash from lockfile
    Algorithm string   // "sha256", "h1" (Go's custom hash)
    Status    string   // "OK", "MISMATCH", "MISSING", "ERROR"
}
```

#### 2b. npm Integrity (`internal/integrity/npm.go`)

**How it works**:
- `package-lock.json` v2+ has `packages.<path>.integrity` field
- Format: `<algorithm>-<base64hash>` (e.g., `sha512-abc123...`)
- npm registry API: `https://registry.npmjs.org/<package>/<version>` returns `dist.integrity` and `dist.shasum`

**Implementation**:
1. Parse `package-lock.json` to extract integrity hashes per package@version
2. For each, query npm registry API for expected integrity
3. Compare — flag mismatches

**Rate limiting**: npm registry allows anonymous requests but may rate-limit. Use concurrency limit of 3, add `User-Agent: depscan/1.0`.

#### 2c. Cache Layer (`internal/integrity/cache.go`)

- Store verified checksums in `~/.depscan/cache/integrity/`
- Key: `ecosystem/package@version` → value: expected hash
- TTL: 7 days
- Avoid re-querying for packages already verified

#### 2d. Scanner Integration (`internal/integrity/integrity.go`)

```go
func VerifyIntegrity(deps []parser.Dependency, projectPath string) []IntegrityResult
```

For each dependency, dispatch to the correct ecosystem verifier.

#### 2e. CLI Integration

- New flag: `--integrity` (enabled by default)
- Terminal output: green checkmark for OK, red X for mismatch
- JSON output includes `integrity_results` array
- Risk score: each integrity mismatch adds 30 points (CRITICAL)

### Files
```
internal/integrity/gomod.go       # Go module checksum verification
internal/integrity/npm.go         # npm integrity hash verification
internal/integrity/cache.go       # Local cache for verified checksums
internal/integrity/integrity.go   # Main VerifyIntegrity dispatcher
```

### Tests
```
internal/integrity/gomod_test.go  # Test with known go.sum entries
internal/integrity/npm_test.go    # Test with mock npm responses
internal/integrity/integrity_test.go  # End-to-end dispatcher test
```

### Acceptance
- `depscan --integrity ./project` verifies all checksums
- Mismatched checksums flagged with CRITICAL severity
- Cache avoids redundant network calls
- Works offline if all packages are cached

---

## Phase 3: Integration & Polish

### Tasks
- [ ] Wire typosquat + integrity into the main scan pipeline
- [ ] Update `internal/scorer/risk.go` to include new check types
- [ ] Update `internal/output/terminal.go` with new output sections
- [ ] Update `internal/output/json.go` with new fields in Report struct
- [ ] Update README.md with new features, flags, and examples
- [ ] Add `--no-typosquat` and `--no-integrity` flags to disable checks
- [ ] Update Makefile with new test targets if needed

### Updated CLI Flags

```
depscan [path] [flags]

Flags:
  --output, -o          JSON output file path
  --no-typosquat        Disable typosquat detection
  --no-integrity        Disable integrity verification
  --typosquat-threshold Similarity threshold (default: 0.75)
  --cache-dir           Custom cache directory (default: ~/.depscan)
  --version             Show version
  --help                Show help
```

### Updated JSON Output

```json
{
  "scan_time": "...",
  "project_path": "...",
  "total_dependencies": 20,
  "vulnerabilities_found": 3,
  "risk_score": 75,
  "risk_level": "HIGH",
  "typosquat_warnings": [
    {
      "package": "lodahs",
      "version": "1.0.0",
      "ecosystem": "npm",
      "confused_with": "lodash",
      "similarity": 0.92,
      "technique": "transposition"
    }
  ],
  "integrity_results": [
    {
      "package": "some-package",
      "version": "1.2.3",
      "ecosystem": "npm",
      "status": "OK",
      "algorithm": "sha512"
    }
  ],
  "results": [...]
}
```

### Files Modified
```
cmd/depscan/scan.go              # Wire new scanners
internal/scorer/risk.go          # Add typosquat/integrity scoring
internal/output/terminal.go      # Add typosquat/integrity sections
internal/output/json.go          # Add new JSON fields
README.md                        # Documentation
```

---

## Implementation Order

```
Phase 0: Fix cmd package (prerequisite, ~1 hour)
  ↓
Phase 1: Typosquat Detection (~4 hours)
  1a. similarity.go → 1b. mutations.go → 1c. popular.go → 1d. typosquat.go → 1e. CLI
  ↓
Phase 2: Integrity Verification (~3 hours)
  2a. gomod.go → 2b. npm.go → 2c. cache.go → 2d. integrity.go → 2e. CLI
  ↓
Phase 3: Integration & Polish (~2 hours)
  Wire everything → update outputs → README → final testing
```

**Total estimate**: ~10 hours

## Dependencies

| New dependency | Package | Why |
|---------------|---------|-----|
| sumdb client | `golang.org/x/mod` | Go checksum database verification |

That's it — one new dependency. All other code is built from scratch to keep depscan lean.

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Typosquat false positives | Configurable threshold, curated popular list (not all packages) |
| npm rate limiting | Concurrency limit of 3, respect Retry-After headers |
| Go sumdb unavailable | Cache results, skip if offline |
| Large dependency lists slow | Parallel checks with semaphore (reuse existing pattern) |
| Popular package list goes stale | 7-day TTL, manual refresh flag |
