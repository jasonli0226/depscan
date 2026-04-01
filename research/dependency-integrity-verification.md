# Dependency Integrity Verification Research

## 1. Go Module Integrity

### How go.sum Works

The `go.sum` file contains cryptographic hashes for every module dependency. Each line has the format:

```
<module-path> <version> h1:<base64-encoded-hash>
<module-path> <version>/go.mod h1:<base64-encoded-hash>
```

**Hash algorithm**: `h1:` prefix = **SHA-256** of the module zip content, encoded as **base64** (not hex). The `/go.mod` variant hashes only the `go.mod` file.

Example from sum.golang.org lookup:
```
golang.org/x/mod v0.34.0 h1:xIHgNUUnW6sYkcM5Jleh05DvLOtwc6RitGHbDk4akRI=
golang.org/x/mod v0.34.0/go.mod h1:ykgH52iCZe79kzLLMhyCUzhMci+nQj+0XkbXpNYtVjY=
```

### Go Module Proxy & Checksum Database (sum.golang.org)

The checksum database at `sum.golang.org` is a **merkle tree-based transparency log** that provides globally agreed-upon hashes for all public Go modules.

**Key URLs**:
- `GET https://sum.golang.org/lookup/{module}@{version}` - Returns go.sum lines + signed tree head
- `GET https://sum.golang.org/latest` - Latest signed tree head
- `GET https://sum.golang.org/tile/{N}/{H}/{L1}/{L2}` - Merkle tree tiles

The response includes a signed proof that can be verified against the built-in public key (hardcoded in Go toolchain).

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `GONOSUMDB` | Comma-separated glob patterns. Modules matching these skip sum.golang.org verification. Does NOT skip go.sum local check. |
| `GONOSUMCHECK` | Comma-separated glob patterns. Modules matching these skip hash comparison entirely (not verified at all). |
| `GOINSECURE` | Modules fetched over HTTP (no TLS). Implies GONOSUMDB. |
| `GONOPROXY` | Modules fetched directly from source, bypassing proxy. |
| `GOPROXY` | Module proxy URL(s). Default: `https://proxy.golang.org,direct` |
| `GOSUMDB` | Checksum DB URL. Default: `sum.golang.org`. Set to `off` to disable. |

**Important**: `GONOSUMDB` means "don't check the global sum DB for this module" but go.sum lines still apply locally. `GONOSUMCHECK` means "don't check hashes at all."

### Programmatic Verification with `golang.org/x/mod/sumdb`

**Package**: `golang.org/x/mod/sumdb` (BSD-3-Clause, maintained by Go team)

```go
import "golang.org/x/mod/sumdb"
```

**Core API**:
```go
type Client struct{}
func NewClient(ops ClientOps) *Client
func (c *Client) Lookup(path, vers string) (lines []string, err error)
func (c *Client) SetGONOSUMDB(list string)
```

**ClientOps interface** - you must implement:
```go
type ClientOps interface {
    ReadRemote(path string) ([]byte, error)      // HTTP fetch from sum DB
    ReadConfig(file string) ([]byte, error)       // Local config (key, latest)
    WriteConfig(file string, old, new []byte) error // Atomic config update
    ReadCache(file string) ([]byte, error)        // Cache lookup
    WriteCache(file string, data []byte)          // Cache write
    Log(msg string)                               // Info logging
    SecurityError(msg string)                     // Fatal security error
}
```

**Usage pattern**:
```go
client := sumdb.NewClient(myClientOps)
client.SetGONOSUMDB(os.Getenv("GONOSUMDB"))

// Lookup returns go.sum lines for the module
lines, err := client.Lookup("golang.org/x/mod", "v0.34.0")
// lines: ["golang.org/x/mod v0.34.0 h1:xIHgNUUnW6sYkcM5Jleh05DvLOtwc6RitGHbDk4akRI=",
//         "golang.org/x/mod v0.34.0/go.mod h1:ykgH52iCZe79kzLLMhyCUzhMci+nQj+0XkbXpNYtVjY="]
```

**To verify a local module**: compute SHA-256 of the zip (or go.mod), base64-encode, prefix with `h1:`, compare against the returned lines.

### Computing Go Module Hashes

Go computes hashes over the **module zip file** (not the source directory). The zip format is specific:
- All files are stored (not deflate) with specific paths
- Prefix: `{module-path}@{version}/`
- Sorted file paths

For `/go.mod` hashes, it's just SHA-256 of the go.mod file content.

```go
import (
    "crypto/sha256"
    "encoding/base64"
    "fmt"
)

func computeGoSumHash(content []byte) string {
    h := sha256.Sum256(content)
    return "h1:" + base64.StdEncoding.EncodeToString(h[:])
}
```

### `go mod verify` Behavior

`go mod verify` checks that the modules in the module cache match the hashes recorded in `go.sum`. It:
1. Reads go.sum for expected hashes
2. Locates each module in `$GOPATH/pkg/mod/cache/download/`
3. Verifies the zip file hash (h1:) and go.mod hash
4. Reports any mismatches

It does NOT contact sum.golang.org - it only checks local go.sum against local cache.

---

## 2. npm Integrity

### package-lock.json Integrity Format

npm uses **Subresource Integrity (SRI)** format in `package-lock.json`:

```json
{
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.23",
      "integrity": "sha512-LgVTMpQtIopCi79SJeDiP0TfWi5CNEc/L/aRdTh3yIvmZXTnheWpKjSZhnvMl8iXbC1tFg9gdHHDMLoV7CnG+w==",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.23.tgz"
    }
  }
}
```

**Format**: `<algorithm>-<base64-hash>`

| Algorithm | Notes |
|-----------|-------|
| `sha1-` | Legacy, only in lockfileVersion 1 (shrinkwrap). **Insecure**. |
| `sha512-` | Default since lockfileVersion 2+. SHA-512 over the **tarball content**. |

**What's hashed**: The entire `.tgz` tarball as downloaded from the registry. This is the compressed archive, not the extracted contents.

**SRI format spec**: https://www.w3.org/TR/SRI/

### npm Registry API for Checksums

**Endpoint**: `GET https://registry.npmjs.org/{package}/{version}`

Returns JSON with `dist` object containing all integrity info:

```json
{
  "dist": {
    "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.23.tgz",
    "shasum": "f113b0378386103be4f6893388c73d0bde7f2c5a",
    "integrity": "sha512-LgVTMpQtIopCi79SJeDiP0TfWi5CNEc/L/aRdTh3yIvmZXTnheWpKjSZhnvMl8iXbC1tFg9gdHHDMLoV7CnG+w==",
    "signatures": [
      {
        "keyid": "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
        "sig": "MEUCIA2uTQrC5HukcLw3blPe1wLDQP/X7t9qj267Vepz1pPqAiEAnKyy+j1OB7IBdcl7+Pmm7eXtY2wiOy2SoMD5Fh2PKR4="
      }
    ],
    "unpackedSize": 1411664,
    "fileCount": 1051
  }
}
```

**Key fields**:
- `dist.integrity` - SRI string (preferred, sha512)
- `dist.shasum` - Legacy SHA-1 hex digest (still present for compat)
- `dist.tarball` - Download URL
- `dist.signatures` - ECDSA registry signatures (npm provenance)

### npm Registry Signatures

npm has introduced **ECDSA registry signatures** (since npm 9.x):
- Signed by the registry when the package is published
- `keyid` identifies the signing key
- `sig` is the ECDSA signature over the integrity hash
- Can be verified using npm's public keys

This provides an additional layer: even if the registry is compromised, signatures can't be forged without the private key.

### Programmatic npm Verification

```go
import (
    "crypto/sha512"
    "encoding/base64"
    "fmt"
    "io"
    "net/http"
    "strings"
)

// VerifyNpmPackage downloads tarball and checks against expected integrity
func VerifyNpmPackage(tarballURL, expectedIntegrity string) error {
    resp, err := http.Get(tarballURL)
    if err != nil {
        return fmt.Errorf("fetch tarball: %w", err)
    }
    defer resp.Body.Close()

    // Parse expected: "sha512-<base64>"
    parts := strings.SplitN(expectedIntegrity, "-", 2)
    if len(parts) != 2 {
        return fmt.Errorf("invalid integrity format")
    }

    // Compute hash of tarball
    hash := sha512.New()
    if _, err := io.Copy(hash, resp.Body); err != nil {
        return fmt.Errorf("read tarball: %w", err)
    }
    computed := base64.StdEncoding.EncodeToString(hash.Sum(nil))

    if computed != parts[1] {
        return fmt.Errorf("integrity mismatch: expected %s, got %s", parts[1], computed)
    }
    return nil
}

// LookupNpmIntegrity queries the registry for expected hash
func LookupNpmIntegrity(pkg, version string) (string, error) {
    url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg, version)
    // GET and parse dist.integrity
    // ...
}
```

---

## 3. Practical Implementation Considerations

### Can We Verify Without Downloading the Full Package?

| Ecosystem | Checksum Only (no download) | Requires Download |
|-----------|---------------------------|-------------------|
| **Go** | YES - sum.golang.org `/lookup` returns hashes directly | Only if verifying local cache |
| **npm** | YES - registry API returns `dist.integrity` without downloading tarball | Only if verifying local node_modules |

**This is key for a scanning tool**: you can look up expected checksums from the authoritative sources (sum.golang.org, registry.npmjs.org) and compare against what's recorded in go.sum / package-lock.json WITHOUT downloading any packages.

### API Rate Limiting

| Service | Rate Limit | Notes |
|---------|-----------|-------|
| **sum.golang.org** | No documented strict limit | Google-hosted, designed for high volume. Uses signed tiles for efficiency. |
| **proxy.golang.org** | ~500 req/min per IP | Documented in Go module proxy docs. |
| **registry.npmjs.org** | No strict limit for metadata reads | Full metadata endpoint can be large; use version-specific endpoint. |
| **npm registry** (writes) | Auth required, rate limited | Not relevant for read-only verification. |

**Recommendations**:
- Cache sum.golang.org tile data aggressively (it's designed for this)
- Use version-specific npm endpoints (`/package/version`) not full metadata
- Implement exponential backoff with jitter
- Batch Go lookups where possible (single tile fetch covers many modules)

### Offline vs Online Verification

| Mode | Go | npm |
|------|----|-----|
| **Offline** | Compare local go.sum hashes against module cache files (like `go mod verify`) | Compare package-lock.json integrity against local node_modules tarballs |
| **Online** | Query sum.golang.org for authoritative hashes, compare against go.sum | Query registry.npmjs.org for authoritative hashes, compare against package-lock.json |

**Recommended hybrid approach**:
1. **Default: Online** - Query authoritative source, compare against lockfile
2. **Fallback: Offline** - If network unavailable, verify local cache matches lockfile
3. **Flag**: `--offline` to force offline mode

---

## 4. Existing Tools

### lockfile-lint
- **GitHub**: `https://github.com/ljharb/lockfile-lint` (now archived/unavailable)
- **Purpose**: Validate npm package-lock.json and yarn.lock
- **Checks**: Package has integrity hash, resolved URL matches registry, no git URLs in production
- **Status**: Limited maintenance; no longer a primary reference

### golang.org/x/mod/sumdb/client
- **Maintained by**: Go team
- **Purpose**: Client for Go checksum database
- **Production ready**: Yes, used by Go toolchain itself
- **Go package**: `golang.org/x/mod/sumdb`

### go mod verify
- **Built into Go toolchain**
- **Behavior**: Verifies module cache matches go.sum (offline only)
- **Limitation**: Does not check go.sum against sum.golang.org
- **Exit code**: 0 if all verified, non-zero if mismatches found

---

## 5. Implementation Recommendations for a Go CLI

### Architecture

```
Scanner CLI
  |
  +-- Go Module Scanner
  |     |-- Parse go.mod + go.sum
  |     |-- sumdb.Client for online verification
  |     |-- Local cache hash comparison for offline
  |     +-- Report: go.sum matches sum.golang.org?
  |
  +-- npm Package Scanner
        |-- Parse package-lock.json
        |-- Registry API client for online verification
        |-- Local node_modules hash comparison for offline
        +-- Report: lockfile matches registry?
```

### Go Packages to Use

| Need | Package | Notes |
|------|---------|-------|
| sumdb client | `golang.org/x/mod/sumdb` | Official, production-ready |
| go.mod parsing | `golang.org/x/mod/modfile` | Official, parse go.mod/go.sum |
| HTTP client | `net/http` | Standard library, with timeout middleware |
| SHA-256 (Go) | `crypto/sha256` | Standard library |
| SHA-512 (npm) | `crypto/sha512` | Standard library |
| Base64 encoding | `encoding/base64` | Standard library |
| JSON parsing | `encoding/json` | Standard library |
| CLI framework | `cobra` or `urfave/cli` | Well-maintained |
| Table output | `tablewriter` or `text/tabwriter` | Standard library has tabwriter |

### Key Implementation Steps

1. **Go Module Verification**:
   - Parse `go.sum` to extract `module@version h1:<hash>` lines
   - Use `sumdb.Client.Lookup(path, version)` to get authoritative hashes
   - Compare h1: hashes (base64-decoded SHA-256)
   - Report mismatches
   - Respect `GONOSUMDB`/`GONOSUMCHECK` env vars

2. **npm Package Verification**:
   - Parse `package-lock.json` to extract `packages.*.integrity` + `resolved`
   - Query `https://registry.npmjs.org/{pkg}/{version}` for `dist.integrity`
   - Compare integrity strings
   - Also check `resolved` URL points to official registry

3. **Offline Mode**:
   - Go: Hash local module cache zips, compare against go.sum
   - npm: Hash local `node_modules/.package-lock.json` cached tarballs, compare against package-lock.json

4. **Output Format**:
   ```
   GO MODULE INTEGRITY SCAN
   ========================
   golang.org/x/mod@v0.34.0     MATCH   (sum.golang.org verified)
   github.com/foo/bar@v1.2.3    MATCH   (sum.golang.org verified)
   github.com/baz/qux@v0.1.0    SKIP    (GONOSUMDB)

   NPM PACKAGE INTEGRITY SCAN
   ==========================
   lodash@4.17.23               MATCH   (registry verified)
   express@4.18.2               MISMATCH (lockfile: sha512-abc..., registry: sha512-xyz...)
   ```

### Edge Cases to Handle

1. **Private modules** (Go): Respect `GONOPROXY`/`GONOSUMDB` - skip or warn
2. **Private packages** (npm): Scoped packages with private registries - skip or warn
3. **Replaced modules** (Go): `go.mod` replace directives - verify replacement, not original
4. **Workspace deps** (Go): `go.work` - resolve workspace before checking
5. **Git dependencies** (npm): Packages installed from git URLs - no integrity check possible
6. **Local paths** (npm): `file:` protocol deps - skip
7. **Deprecated versions**: Registry may return different metadata structure

### Performance Optimization

1. **Batch Go lookups**: sum.golang.org uses merkle tiles; a single tile fetch covers many modules
2. **Parallel npm lookups**: Use goroutines with semaphore (e.g., 10 concurrent)
3. **Cache registry responses**: Store in `~/.cache/depscan/` with TTL
4. **Stream go.sum parsing**: Process line-by-line, don't load entire file into memory

---

## Summary

| Aspect | Go | npm |
|--------|----|-----|
| **Hash algorithm** | SHA-256 (h1:) | SHA-512 (default) |
| **Hash encoding** | Base64 | Base64 (SRI format) |
| **What's hashed** | Module zip / go.mod | Tarball (.tgz) |
| **Authoritative source** | sum.golang.org (merkle tree) | registry.npmjs.org (API) |
| **Lookup without download** | YES (`/lookup` API) | YES (`/package/version` API) |
| **Go package** | `golang.org/x/mod/sumdb` | Custom HTTP client |
| **Env var support** | GONOSUMDB, GONOSUMCHECK | N/A (scoped registries) |
| **Registry signatures** | Merkle tree + signed tree head | ECDSA signatures (npm provenance) |
