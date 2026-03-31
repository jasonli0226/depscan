package integrity

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jasonli0226/depscan/internal/parser"
)

const npmRegistryURL = "https://registry.npmjs.org"

// npmPackageMeta represents the metadata from npm registry for a specific version.
type npmPackageMeta struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Shasum    string `json:"shasum"`
		Integrity string `json:"integrity"`
		Tarball   string `json:"tarball"`
	} `json:"dist"`
}

// npmLockPackage represents a package entry in package-lock.json v2+.
type npmLockPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
}

// npmLockfile represents the structure of package-lock.json.
type npmLockfile struct {
	Packages map[string]npmLockPackage `json:"packages"`
}

var npmClient = &http.Client{Timeout: 15 * time.Second}

// parseNpmLockIntegrity reads package-lock.json and extracts integrity hashes.
func parseNpmLockIntegrity(projectPath string) (map[string]string, error) {
	lockPath := filepath.Join(projectPath, "package-lock.json")

	data, err := readLockfile(lockPath)
	if err != nil {
		return nil, err
	}

	var lockfile npmLockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("invalid package-lock.json: %w", err)
	}

	// Build a map of name@version -> integrity
	integrityMap := make(map[string]string)
	for pkgPath, pkg := range lockfile.Packages {
		if pkgPath == "" || pkg.Integrity == "" || pkg.Name == "" {
			continue
		}
		key := pkg.Name + "@" + pkg.Version
		integrityMap[key] = pkg.Integrity
	}

	return integrityMap, nil
}

// readLockfile reads a lockfile from disk.
func readLockfile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read lockfile: %w", err)
	}
	return data, nil
}

// fetchNpmRegistryIntegrity queries the npm registry for the expected
// integrity hash of a specific package version.
func fetchNpmRegistryIntegrity(name, version string) (*npmPackageMeta, error) {
	url := fmt.Sprintf("%s/%s/%s", npmRegistryURL, name, version)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "depscan/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := npmClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm registry request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %s@%s not found", name, version)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("npm registry returned status %d: %s", resp.StatusCode, string(body))
	}

	var meta npmPackageMeta
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("failed to parse npm response: %w", err)
	}

	return &meta, nil
}

// verifyNpmPackages checks npm package integrity hashes against the registry.
func verifyNpmPackages(deps []parser.Dependency, projectPath string) []IntegrityResult {
	lockIntegrity, err := parseNpmLockIntegrity(projectPath)
	if err != nil {
		results := make([]IntegrityResult, 0, len(deps))
		for _, dep := range deps {
			results = append(results, IntegrityResult{
				Package: dep,
				Status:  StatusMissing,
				Error:   "package-lock.json not found or unreadable",
			})
		}
		return results
	}

	type indexedResult struct {
		idx    int
		result IntegrityResult
	}

	sem := make(chan struct{}, 10)
	resultCh := make(chan indexedResult, len(deps))

	var wg sync.WaitGroup
	for i, dep := range deps {
		wg.Add(1)
		go func(i int, dep parser.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := verifySingleNpmPackage(dep, lockIntegrity)
			resultCh <- indexedResult{idx: i, result: result}
		}(i, dep)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	results := make([]IntegrityResult, len(deps))
	for ir := range resultCh {
		results[ir.idx] = ir.result
	}

	return results
}

// verifySingleNpmPackage checks a single npm package's integrity against the
// lockfile and the npm registry.
func verifySingleNpmPackage(dep parser.Dependency, lockIntegrity map[string]string) IntegrityResult {
	key := dep.Name + "@" + dep.Version
	lockHash, hasLock := lockIntegrity[key]

	if !hasLock {
		return IntegrityResult{
			Package: dep,
			Status:  StatusMissing,
			Error:   "no integrity hash in package-lock.json",
		}
	}

	meta, err := fetchNpmRegistryIntegrity(dep.Name, dep.Version)
	if err != nil {
		return IntegrityResult{
			Package: dep,
			Status:  StatusError,
			Error:   err.Error(),
		}
	}

	expectedHash := meta.Dist.Integrity
	if expectedHash == "" {
		expectedHash = "sha1-" + meta.Dist.Shasum
	}

	algorithm := "sha512"
	if idx := strings.Index(expectedHash, "-"); idx != -1 {
		algorithm = expectedHash[:idx]
	}

	if lockHash != expectedHash {
		return IntegrityResult{
			Package:   dep,
			Status:    StatusMismatch,
			Algorithm: algorithm,
			Expected:  expectedHash,
			Actual:    lockHash,
		}
	}

	return IntegrityResult{
		Package:   dep,
		Status:    StatusOK,
		Algorithm: algorithm,
		Expected:  expectedHash,
		Actual:    lockHash,
	}
}
