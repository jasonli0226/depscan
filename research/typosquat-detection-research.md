# Typosquatting Detection Research for Go CLI Tool

## 1. String Similarity Algorithms

### Recommended Hierarchy for Package Names

| Algorithm | Best For | Go Library | Notes |
|-----------|----------|------------|-------|
| **Damerau-Levenshtein** | Primary detection (catches transpositions) | `go-edlib`, `strutil` | Superset of Levenshtein; detects adjacent swaps which are the #1 typing error |
| **Jaro-Winkler** | Short strings, prefix-heavy names | `go-edlib`, `strutil` | Prefers prefix matches - excellent for package names where typos cluster at start |
| **Sorensen-Dice (Q-gram)** | Fast pre-filtering | `go-edlib`, `strutil` | Use as cheap first-pass filter before expensive algorithms |
| **Levenshtein** | Baseline, registry-level blocking | `go-edlib`, `strutil` | npm itself uses this at registration time |
| **Cosine Similarity** | Semantic substitution detection | `go-edlib` | Combined with word embeddings for meaning-based attacks |

### Recommendation
**Use Damerau-Levenshtein as primary, Jaro-Winkler as secondary, Sorensen-Dice as pre-filter.**

- Damerau-Levenshtein distance <= 2 catches ~45% of real attacks (per PyPI analysis)
- Jaro-Winkler similarity >= 0.85 catches most remaining cases
- Sorensen-Dice threshold >= 0.7 as cheap bloom filter

### Go Libraries (Well-Maintained)

| Library | Stars | Algorithms | Last Updated |
|---------|-------|------------|-------------|
| **`github.com/hbollon/go-edlib`** | 598 | Levenshtein, Damerau-Levenshtein (OSA + Adjacent), Jaro-Winkler, Cosine, LCS, Hamming, Jaccard, QGram, Sorensen-Dice | Active, 100% test coverage, Go 1.13+ |
| **`github.com/adrg/strutil`** | 415 | Levenshtein, Jaro, Jaro-Winkler, Smith-Waterman-Gotoh, Sorensen-Dice, Jaccard, Overlap Coefficient, Hamming | Clean interface, `StringMetric` pattern |

**Recommendation: `go-edlib`** - more algorithms, active development, Unicode compatible, built-in fuzzy search.

---

## 2. Typosquatting Techniques (Taxonomy)

### High-Priority Techniques (Implement First)

| Technique | Example | Description | Detection Strategy |
|-----------|---------|-------------|-------------------|
| **Omission** | `requests` -> `reqests` | Drop single char | Damerau-Levenshtein = 1 |
| **Transposition** | `requests` -> `reqeusts` | Swap adjacent chars | Damerau-Levenshtein = 1 (Levenshtein = 2) |
| **Repetition** | `requests` -> `rrequests` | Double a char | Damerau-Levenshtein = 1 |
| **Homoglyph** | `lodash` -> `1odash` | Lookalike chars (l/1/I, O/0, rn/m) | `mtibben/confusables` (Unicode TR39) |
| **Prefix/Suffix Addition** | `dateutil` -> `python3-dateutil` | Add common prefixes/suffixes | Suffix/prefix matching + download ratio |
| **Delimiter Modification** | `cross-env` -> `crossenv` | Change/remove separators | Normalize delimiters before comparison |

### Medium-Priority Techniques

| Technique | Example | Description | Detection Strategy |
|-----------|---------|-------------|-------------------|
| **Replacement** | `requests` -> `requezts` | Adjacent keyboard keys | Keyboard adjacency map + Levenshtein |
| **Vowel Swap** | `requests` -> `raquests` | Replace vowels | Regex vowel patterns + edit distance |
| **Word Order** | `python-nmap` -> `nmap-python` | Reorder words | Tokenize on delimiters, permute |
| **Plural** | `request` vs `requests` | Add/remove trailing 's' | Exact match after stripping 's' |
| **Scope Confusion** | `@scope/pkg` vs `scopee/pkg` | npm scope manipulation | Scope-aware normalization |
| **Combosquatting** | `lodash` -> `lodash-utils` | Add common suffixes | Known suffix list + popularity delta |
| **Bitsquatting** | `google` -> `coogle` | Single-bit memory errors | Bit-flip generation (all 1-bit variants) |

### Low-Priority / Advanced

| Technique | Example | Description |
|-----------|---------|-------------|
| **Semantic Substitution** | `bz2file` -> `bzip` | Replace word with synonym |
| **Homophonic** | `uglify-js` -> `uglifi.js` | Phonetic similarity |
| **Impersonation Squatting** | `meta-llama/...` -> `facebook-llama/...` | Hierarchical name spoofing (HuggingFace, Go modules) |
| **Compound Squatting** | `@typescript-eslint/eslint-plugin` -> `@typescript_eslinter/eslint` | Scope + word mutation |
| **Slopsquatting** | LLM-hallucinated package names | AI-generated fake package names |

---

## 3. Existing Tools & Databases

### CLI Tools

| Tool | Language | Ecosystems | Approach | Notes |
|------|----------|------------|----------|-------|
| **`andrew/typosquatting`** (Ruby gem) | Ruby | PyPI, npm, Cargo, Go, Maven, NuGet, Composer, Hex, Pub, GitHub Actions | Variant generation + registry check | 14 algorithms, SBOM support, `ecosyste.ms` API |
| **Falcn** | Go | npm, PyPI, Go, more | Levenshtein + Jaro-Winkler + homoglyphs + ML scoring | Production-grade, ONNX ML model, CI/CD native, <60ms fast mode |
| **MITRE HipCheck** (`mitre/typo` plugin) | Rust | npm | Lexical similarity analysis | Plugin architecture |
| **URLInsane** | Python | Domains + packages | Multi-algorithm + OSINT | Cross-domain investigation |
| **OSSGadget** (Microsoft) | C# | Multi-ecosystem | Typo generation + check | `oss-find-squats` command |
| **Socket** | Proprietary | npm, PyPI, Go | Real-time detection | Subscription-based |
| **typomania** | Rust | crates.io | Powers crates.io's own detection | Rust Foundation maintained |
| **typogard** | JS | npm | Transitive dependency checking |

### Academic Systems

| System | Key Innovation | FP Reduction |
|--------|---------------|--------------|
| **TypoSmart** (Purdue + Socket, 2025) | Embedding-based similarity + metadata verification | 70.4% FP reduction vs prior work; removed 3,658 typosquats in 1 month |
| **SpellBound** (USENIX 2020) | Lexical similarity + download count analysis | 0.5% FP rate |
| **Typomind** | 12 heuristic rules + FastText embeddings | ~0.1% malware in reports |

### What Existing Tools Do NOT Do Well
- No Go-native comprehensive typosquat scanner (Falcn is closest but enterprise-focused)
- Most tools have high false positive rates
- Limited npm scope confusion detection
- Go module path squatting (hierarchical names) is underserved

### Datasets

| Dataset | Size | Content |
|---------|------|---------|
| **ecosyste-ms/typosquatting-dataset** | 143 entries | Confirmed attacks mapped to targets with technique classification |
| **OpenSSF malicious-packages** | 1000s | Large but lacks target mapping |
| **Datadog dataset** | 17,000+ | Largest, but most entries lack target identification |

---

## 4. Homoglyph / Confusable Detection

### Go Libraries

| Library | Stars | Implementation | Notes |
|---------|-------|---------------|-------|
| **`github.com/mtibben/confusables`** | 34 | Unicode TR39 skeleton algorithm | Best option - `Skeleton()` normalizes to canonical form, `Confusable()` checks if two strings are confusable. Updated Oct 2025. |
| **`github.com/NebulousLabs/glyphcheck`** | 47 | Go source code scanner | Detects homoglyphs in `.go` files (import paths, variables). Not for package name comparison. |
| **`github.com/picatz/homoglyphr`** | 10 | Domain name character generator | Generates confusable variants. |

### Recommendation
Use **`mtibben/confusables`** for package name homoglyph detection:
```go
// Check if two package names are confusable
confusables.Confusable("lodash", "1odash") // true
confusables.Skeleton("𝔭𝒶ỿ𝕡𝕒ℓ")        // "paypal"
```

### Manual Homoglyph Groups (for quick checks)
```
l, 1, I, |, !
O, 0, Q
rn, m, rn
cl, d
vv, w
5, S, s
8, B
6, G
```

---

## 5. Building a "Popular Package" Baseline

### npm: Download Counts

**API: `https://api.npmjs.org/downloads/point/last-month/PACKAGE`**
- Returns `{downloads: N}` for any package
- Rate limited but per-package calls are fine

**Bulk Data: `https://replicate.npmjs.com/_all_docs?include_docs=true`**
- Full CouchDB replication endpoint (~5M packages)
- Includes download counts, depends on which metrics
- Can filter by `downloads.last-week` or `downloads.last-month`

**Alternative: `https://api.npms.io/v2/search?q=...&size=100`**
- npms.io provides popularity scores (0-1) combining downloads, stars, etc.
- Search with `q=popularity:0.5` for packages above threshold

**Recommended approach for npm baseline:**
1. Use npms.io search API to get top packages by popularity score
2. Paginate through `popularity:>0.9` (top ~1000), then `>0.7` (top ~5000), etc.
3. Cache locally with periodic refresh
4. Alternative: Download the full npm registry dump (CouchDB) and extract top N by download count

### Go: Module Popularity

**Challenge: Go module proxy has NO download count API.**

**Best sources for Go popularity:**
1. **`https://proxy.golang.org/`** - Can check if module exists via `GET /$module/@v/list`, but no popularity metrics
2. **`https://pkg.go.dev/`** - Has import counts but no public API
3. **`https://go.dev/explore/`** - Curated list of notable packages
4. **`https://api.golang.org/search`** - Basic search, no popularity
5. **OpenSSF Scorecard** - `https://api.scorecard.dev/repos/` - Security scores for known repos
6. **GitHub stars/forks** via GitHub API - Proxy for popularity
7. **`ecosyste.ms` API** - `https://packages.ecosyste.ms/api/v1/registries/pypi.org/packages?sort=downloads` - Has Go packages too

**Recommended approach for Go baseline:**
1. Start with Go standard library + `golang.org/x/` packages (always safe)
2. Use `ecosyste.ms` API: `GET /api/v1/registries/pypi.org/packages` supports Go registry too
3. Scrape `go.dev/explore/` for notable packages
4. Cross-reference with GitHub API for stars > threshold
5. Consider importing the `OpenSSF criticality_scores` dataset

### Cross-Ecosystem: `ecosyste.ms`

**The best unified API for package metadata across ecosystems:**

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/registries/{registry}/packages` | List packages with sorting/filtering |
| `GET /api/v1/registries/{registry}/package_names?prefix=X` | Search by prefix (typosquat detection!) |
| `GET /api/v1/registries/{registry}/package_names?postfix=X` | Search by postfix |
| Supported registries | `npmjs.org`, `pypi.org`, `rubygems.org`, `crates.io`, `golang.org`, `maven.org`, etc. |

This is what `andrew/typosquatting` Ruby gem uses. Perfect for both baseline building AND variant checking.

---

## 6. Concrete Implementation Recommendations

### Architecture for a Go CLI Tool

```
1. Variant Generator (pure Go, no network)
   ├── Omission, Transposition, Repetition
   ├── Homoglyph (via mtibben/confusables)
   ├── Keyboard Adjacency (replacement map)
   ├── Prefix/Suffix (common patterns list)
   ├── Delimiter Modification
   ├── Vowel Swap, Plural, Word Order
   └── Combosquatting (known suffix list)

2. Similarity Engine (go-edlib)
   ├── Pre-filter: Sorensen-Dice >= 0.7
   ├── Primary: Damerau-Levenshtein <= 2
   ├── Secondary: Jaro-Winkler >= 0.85
   └── Homoglyph: mtibben/confusables

3. Registry Checker
   ├── npm: registry.npmjs.org API (check if package exists)
   ├── Go: proxy.golang.org API (check if module exists)
   └── Fallback: ecosyste.ms API (unified, but rate limited)

4. Popularity Baseline (cached locally)
   ├── npm: npms.io top packages + download counts
   ├── Go: go.dev/explore + ecosyste.ms + GitHub stars
   └── Cache: SQLite or embedded JSON, refresh weekly

5. Risk Scorer
   ├── Download ratio: suspicious / popular (low ratio = suspicious)
   ├── Creation date: newer than popular package? (must be younger)
   ├── Author overlap: different author from popular package?
   ├── Repository URL: exists? matches author?
   └── Metadata completeness: empty description, no repo, no license = suspicious
```

### Key Design Decisions

1. **Generate variants first, then check registry** (not compare against all packages)
   - Much faster: checking 100-200 variants vs comparing against 5M packages
   - This is the approach used by `andrew/typosquatting` and `typogenerator`

2. **Three-tier detection:**
   - **Tier 1 (fast, offline):** Edit distance + homoglyph on dependency list vs cached popular packages
   - **Tier 2 (network):** Generate variants, check if they exist on registry
   - **Tier 3 (deep):** Metadata analysis, author verification, download patterns

3. **False positive reduction (from TypoSmart research):**
   - Filter out packages that predate the popular package (can't be typosquats)
   - Filter by download ratio (legitimate similar names often have their own following)
   - Check author/maintainer overlap
   - Verify repository URL exists and points to legitimate source

### Specific Go Dependencies

```go
// go.mod dependencies
require (
    github.com/hbollon/go-edlib    // String similarity (primary engine)
    github.com/mtibben/confusables // Unicode TR39 homoglyph detection
    // OR adapt strategies from zntrio/typogenerator for variant generation
)
```

**Note on `zntrio/typogenerator`:** Already implements 14 strategies in Go including Omission, Repetition, Transposition, Homoglyph, BitSquatting, VowelSwap, etc. Updated Mar 2026. Could be used directly or as reference for variant generation. However, it's more focused on domain names than package names - you'll need to adapt delimiter handling and add package-specific strategies (scope confusion, combosquatting).

### Performance Targets (from Falcn)
- Fast mode (heuristics only, no network): < 100ms
- Full scan (with registry checks): 2-5 seconds
- Batch (100 packages): < 10 seconds

### Minimal Viable Implementation Order

1. **Phase 1:** Variant generator (adapt from typogenerator) + Damerau-Levenshtein (go-edlib)
2. **Phase 2:** Homoglyph detection (mtibben/confusables)
3. **Phase 3:** npm/Go registry existence checks
4. **Phase 4:** Popularity baseline + risk scoring
5. **Phase 5:** Metadata verification (creation date, author, repo URL)
