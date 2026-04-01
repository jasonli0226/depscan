# Depscan Code Review: Typosquat + Integrity

**Reviewer**: Jas
**Date**: 2026-04-01
**Scope**: `cmd/`, `internal/typosquat/`, `internal/integrity/`, `internal/scorer/`, `internal/output/`

---

## Summary

Solid implementation across all 4 phases. Build is clean, 28/28 tests pass, end-to-end smoke test works. The architecture is sensible — no new dependencies added, clean separation of concerns.

That said, there are **3 bugs**, **several correctness issues**, and a handful of style/convention things to fix before this ships.

---

## CRITICAL (Must Fix)

### C1. Duplicate entry in `topGoModules` — compilation risk
**File**: `internal/typosquat/popular.go`

`github.com/jmoiron/sqlx` appears twice in the slice. More critically, some entries in this list are **sub-packages** of other entries (e.g., `github.com/stretchr/testify/mock`, `github.com/stretchr/testify/assert`, `github.com/stretchr/testify/require` are sub-packages of `github.com/stretchr/testify`). These shouldn't be in the top-level list because:

1. They cause false positives — `github.com/stretchr/testify` will always match its own sub-packages at high similarity
2. They bloat the mutation map unnecessarily

**Fix**: Deduplicate, remove sub-packages, keep only top-level modules.

### C2. `go.sum` parser only captures one hash per line
**File**: `internal/integrity/gomod.go` (parseGoSum)

go.sum entries can have multiple hashes per module@version line (e.g., `module@version h1:xxx go.mod h1:yyy`). The current parser only captures the first hash via `hashes_field = parts[1]`, then appends it. But `parts[2]` (which would be the second hash on the same key) is never reached because the next iteration sees a new line.

Actually wait — re-reading the code, the key is the same for both hash lines, so `append(entries[key], ...)` should accumulate them. But the issue is that go.sum format is:

```
github.com/fatih/color v1.18.0 h1:S8gINlzdQ840/4pfAwic/ZE0djQEH3wM94VfqLTZcOM=
github.com/fatih/color v1.18.0/go.mod h1:4FelSpRwEGDpQ12mAdzqdOukCy4u8WUtOY6lkT/6HfU=
```

The `/go.mod` variant uses `@` in the key (after our parsing). But with the current format detection, `parts[0]` = `github.com/fatih/color`, `parts[1]` = `v1.18.0`, `parts[2]` = `h1:...`. This works fine. The `/go.mod` line has `parts[0]` = `github.com/fatih/color`, `parts[1]` = `v1.18.0/go.mod`, which means the key becomes `github.com/fatih/color@v1.18.0/go.mod`. That's actually correct for go.sum semantics.

**Downgrade**: Not critical after re-analysis. But the go.sum parser should be more robust.

### C3. `EnsurePopularPackages` cache freshness check is wrong
**File**: `internal/typosquat/popular.go` line ~130

```go
if len(cached.GoModules) > 0 || len(cached.NpmPackages) > 0 {
    return cached, nil
}
```

This uses `||` (OR). If GoModules is loaded but NpmPackages is empty (because the npm fetch failed and was saved as empty), the cache is considered "fresh" forever. The npm packages will never be re-fetched.

**Fix**: Use `&&` instead of `||`, or check expiry separately for each ecosystem.

---

## HIGH (Should Fix)

### H1. `buildMutationMap` is extremely expensive at scale
**File**: `internal/typosquat/typosquat.go`

For each popular package, `GenerateMutations` produces ~50 mutations. With 150+ Go modules + 500 npm packages, this builds a map of ~30,000+ entries. Each entry requires string operations (slicing, concatenation). This happens on **every scan invocation**.

**Impact**: First scan will be slow (~2-5s just for mutation map building). Subsequent scans hit the cache for popular packages but still rebuild the mutation map.

**Fix**: Cache the mutation map alongside popular packages. Or generate it lazily on first use and cache it.

### H2. npm integrity verification makes N sequential HTTP requests
**File**: `internal/integrity/npm.go` (verifyNpmPackages)

For each npm dependency, a separate HTTP request is made to the npm registry. A project with 100 npm deps = 100 sequential requests at 15s timeout each = worst case 25 minutes.

**Fix**: Use concurrent HTTP requests with a semaphore (e.g., 10 concurrent). Use `errgroup` or a worker pool.

### H3. `checkDependency` lowercases dep name but mutation map keys are already lowercase
**File**: `internal/typosquat/typosquat.go`

`buildMutationMap` already lowercases: `pkgLower := strings.ToLower(pkg)`. But `checkDependency` also lowercases: `depName := strings.ToLower(dep.Name)`. The double-lowercasing is harmless but the real issue is:

If a dep name is `GITHUB.COM/USER/PKG` (uppercase), it gets lowercased for lookup. But the `refs` set also stores lowercase keys. The similarity check does `strings.ToLower(popularPkg)` redundantly since `buildSet` already lowercases.

**Impact**: Performance waste (double lowercasing on every comparison). Not a bug.

### H4. Ecosystem casing mismatch
**File**: `internal/integrity/integrity.go` (filterByEcosystem)

The parser outputs `"Go"` for Go modules and `"npm"` for npm packages. But `filterByEcosystem` is called with literal `"Go"` and `"npm"`. This works by coincidence — but it's fragile.

**Fix**: Define ecosystem constants or use case-insensitive matching.

### H5. `truncate` function breaks multi-byte UTF-8 strings
**File**: `internal/output/terminal.go`

```go
return s[:maxLen-3] + "..."
```

This slices by byte offset, not rune offset. If `maxLen-3` falls in the middle of a multi-byte character (common in CJK text), it produces invalid UTF-8.

**Fix**: Use `[]rune(s)` for the truncation, or use `utf8.RuneCountInString`.

---

## MEDIUM (Nice to Fix)

### M1. `commonPrefixes` and `commonSuffixes` are identical
**File**: `internal/typosquat/mutations.go`

```go
var commonPrefixes = []string{"-", "-cli", "-core", ...}
var commonSuffixes = []string{"-", "-cli", "-core", ...}
```

They're the same slice. This isn't wrong (prefix appends, suffix prepends), but the variable names are confusing. The comments say "prefixMutations appends common suffixes" which is contradictory.

**Fix**: Rename to `commonAffixes` and use a single shared slice. Fix the misleading comments.

### M2. `homoglyphMap` only maps lowercase characters
**File**: `internal/typosquat/mutations.go`

Only lowercase `o`, `l`, `i`, etc. are mapped. Package names with uppercase chars (e.g., `OAuth2`) won't get homoglyph mutations for the uppercase variants.

**Fix**: Add uppercase mappings or lowercase the input in `homoglyphMutations`.

### M3. Dead code: `goSumEntry` struct unused
**File**: `internal/integrity/gomod.go`

The `goSumEntry` struct is defined but never used. The parser uses `map[string][]string` directly.

**Fix**: Remove it.

### M4. `round2` function defined but never used
**File**: `internal/typosquat/similarity.go`

**Fix**: Remove it.

### M5. `rootCmd.PersistentPreRunE` is a no-op
**File**: `cmd/depscan/root.go`

```go
PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
    return nil
},
```

**Fix**: Remove it unless it's planned for future use.

### M6. npm lockfile path uses string concatenation instead of `filepath.Join`
**File**: `internal/integrity/npm.go`

```go
lockPath := projectPath + "/package-lock.json"
```

**Fix**: Use `filepath.Join(projectPath, "package-lock.json")`.

### M7. No validation on `--typosquat-threshold` flag
**File**: `cmd/depscan/scan.go`

User can pass `--typosquat-threshold -5` or `--typosquat-threshold 999` and it'll be accepted.

**Fix**: Add `MarkFlagRequired` or validate in `RunE`.

### M8. Test uses `fmt.Printf` for debug output instead of `t.Log`
**File**: `internal/typosquat/typosquat_test.go` line 26

```go
fmt.Printf("Go modules loaded: %d, npm packages loaded: %d\n", ...)
```

**Fix**: Use `t.Logf(...)`.

---

## LOW (Style / Convention)

### L1. `hashes_field` uses snake_case
**File**: `internal/integrity/gomod.go`

Go uses camelCase. Should be `hashField`.

### L2. `CalculateRiskScore` (legacy) still exists
**File**: `internal/scorer/risk.go`

The legacy `CalculateRiskScore` is no longer called by the scan command. It's dead code.

### L3. Missing `Description` on test subtests
Several test cases could benefit from more descriptive names for failure debugging.

### L4. `math` import only used for `round2`
If `round2` is removed (M4), the `math` import can also be removed.

---

## Architecture Observations

### Good
- Clean package separation: `typosquat/`, `integrity/`, `scorer/`, `output/`
- Zero new dependencies — all similarity algorithms implemented from scratch
- Proper error wrapping with `%w`
- Pre-allocated slices
- Table-driven tests with proper helpers

### Concerns
- The `topGoModules` list will need maintenance. Consider auto-generating from Go module proxy download stats.
- The `EnsurePopularPackages` function has side effects (network I/O, file I/O) hidden behind a simple function call. Consider making the data source injectable for testing.
- No timeout/progress indicator for the npm fetch — user sees no output while waiting for network.

---

## Recommended Fix Priority

1. **C1** — Deduplicate topGoModules, remove sub-packages
2. **C3** — Fix cache freshness logic (`||` → `&&`)
3. **H2** — Concurrent npm integrity checks
4. **H5** — UTF-8 safe truncate
5. **M1** — Rename confusing affix variables
6. **M3/M4/M5/M6** — Clean up dead code and style issues
7. Everything else can be deferred to a follow-up PR
