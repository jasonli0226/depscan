package typosquat

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const cacheTTL = 7 * 24 * time.Hour

// PopularPackages holds the cached list of popular packages per ecosystem.
type PopularPackages struct {
	GoModules   []string  `json:"go_modules"`
	NpmPackages []string  `json:"npm_packages"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CacheDir returns the cache directory path, creating it if needed.
func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	dir := filepath.Join(home, ".depscan", "cache", "typosquat")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("cannot create cache directory: %w", err)
	}
	return dir, nil
}

func cachePath() (string, error) {
	dir, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "popular.json"), nil
}

// LoadPopularPackages loads cached popular packages. Returns empty struct
// if cache is missing or expired.
func LoadPopularPackages() (*PopularPackages, error) {
	path, err := cachePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return &PopularPackages{}, nil
	}

	var pkgs PopularPackages
	if err := json.Unmarshal(data, &pkgs); err != nil {
		return &PopularPackages{}, nil
	}

	// Check expiry
	if time.Since(pkgs.UpdatedAt) > cacheTTL {
		return &PopularPackages{}, nil
	}

	return &pkgs, nil
}

// SavePopularPackages persists popular packages to cache.
func SavePopularPackages(pkgs *PopularPackages) error {
	pkgs.UpdatedAt = time.Now()

	path, err := cachePath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(pkgs, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal cache: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("cannot write cache: %w", err)
	}
	return nil
}

// topGoModules is a curated fallback list of popular Go modules.
// Used when the proxy is unavailable or as a baseline.
var topGoModules = []string{
	"github.com/gin-gonic/gin",
	"github.com/go-chi/chi",
	"github.com/labstack/echo",
	"github.com/gorilla/mux",
	"github.com/fiber/fiber",
	"golang.org/x/crypto",
	"golang.org/x/net",
	"golang.org/x/oauth2",
	"golang.org/x/text",
	"google.golang.org/grpc",
	"google.golang.org/protobuf",
	"github.com/stretchr/testify",
	"github.com/go-sql-driver/mysql",
	"github.com/lib/pq",
	"github.com/jackc/pgx",
	"go.uber.org/zap",
	"github.com/sirupsen/logrus",
	"github.com/rs/zerolog",
	"github.com/spf13/cobra",
	"github.com/spf13/viper",
	"gopkg.in/yaml.v3",
	"github.com/go-playground/validator",
	"github.com/golang-jwt/jwt",
	"github.com/redis/go-redis",
	"github.com/segmentio/kafka-go",
	"github.com/nats-io/nats.go",
	"github.com/prometheus/client_golang",
	"go.etcd.io/etcd/client/v3",
	"github.com/docker/docker",
	"github.com/containernetworking/cni",
	"k8s.io/client-go",
	"github.com/aws/aws-sdk-go",
	"github.com/aws/aws-sdk-go-v2",
	"github.com/google/uuid",
	"github.com/pkg/errors",
	"github.com/fsnotify/fsnotify",
	"github.com/urfave/cli",
	"github.com/mitchellh/mapstructure",
	"github.com/imdario/mergo",
	"github.com/caarlos0/env",
	"go.uber.org/atomic",
	"go.uber.org/multierr",
	"golang.org/x/sync",
	"golang.org/x/time",
	"gorm.io/gorm",
	"github.com/glebarez/sqlite",
	"github.com/mattn/go-sqlite3",
	"github.com/jmoiron/sqlx",
	"github.com/go-redis/redis",
	"github.com/olivere/elastic",
	"github.com/elastic/go-elasticsearch",
	"github.com/dgrijalva/jwt-go",
	"github.com/casbin/casbin",
	"github.com/gorilla/websocket",
	"github.com/gorilla/handlers",
	"github.com/gorilla/sessions",
	"github.com/gorilla/securecookie",
	"github.com/gorilla/csrf",
	"github.com/microcosm-cc/bluemonday",
	"github.com/russellhaering/goxmldsig",
	"github.com/xeipuuv/gojsonschema",
	"github.com/tidwall/gjson",
	"github.com/json-iterator/go",
	"github.com/mailru/easyjson",
	"github.com/patrickmn/go-cache",
	"github.com/allegro/bigcache",
	"github.com/coocood/freecache",
	"github.com/bluele/gcache",
	"github.com/dgraph-io/badger",
	"github.com/boltdb/bolt",
	"go.etcd.io/bbolt",
	"github.com/syndtr/goleveldb",
	"github.com/tecbot/gorocksdb",
	"github.com/cockroachdb/pebble",
	"github.com/vmihailenco/msgpack",
	"github.com/ugorji/go/codec",
	"github.com/golang/protobuf",
	"github.com/gogo/protobuf",
	"github.com/grpc-ecosystem/grpc-gateway",
	"github.com/soheilhy/cmux",
	"github.com/hashicorp/consul",
	"github.com/hashicorp/vault",
	"github.com/go-chi/cors",
	"github.com/go-chi/render",
	"github.com/go-chi/jwtauth",
	"github.com/unrolled/secure",
	"github.com/justinas/nosurf",
	"github.com/go-http-utils/headers",
	"github.com/valyala/fasthttp",
	"github.com/valyala/fasttemplate",
	"github.com/influxdata/influxdb-client-go",
	"github.com/xdg/scram",
	"github.com/libsql/libsql-client-go",
	"github.com/charmbracelet/bubbletea",
	"github.com/charmbracelet/lipgloss",
	"github.com/pterm/pterm",
	"github.com/fatih/color",
	"github.com/alecthomas/chroma",
	"github.com/jesseduffield/lazygit",
	"github.com/cli/cli",
	"github.com/charmbracelet/glow",
	"github.com/go-git/go-git",
	"github.com/go-chi/chi/v5",
	"github.com/emicklei/go-restful",
	"github.com/julienschmidt/httprouter",
	"github.com/pressly/goose/v3",
	"github.com/golang-migrate/migrate",
	"github.com/remiges/go-migrate",
	"github.com/testcontainers/testcontainers-go",
	"github.com/ory/dockertest",
	"github.com/onsi/ginkgo",
	"github.com/onsi/gomega",
	"github.com/pmezard/go-difflib",
	"github.com/davecgh/go-spew",
	"github.com/google/go-cmp",
	"github.com/kr/pretty",
	"github.com/matryer/is",
	"github.com/bradleyfalzon/ghinstallation",
	"github.com/shurcooL/githubv4",
	"github.com/google/go-github",
	"go.opentelemetry.io/otel",
	"go.opentelemetry.io/otel/sdk",
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp",
	"github.com/open-telemetry/opentelemetry-go-contrib",
	"github.com/hashicorp/go-retryablehttp",
	"github.com/hashicorp/go-cleanhttp",
	"github.com/hashicorp/go-multierror",
	"github.com/minio/minio-go",
	"github.com/avast/retry-go",
	"github.com/cenkalti/backoff",
	"github.com/sethvargo/go-retry",
}

// FetchGoModules returns popular Go module names. Uses the curated list
// as the primary source since the Go proxy doesn't provide popularity rankings.
func FetchGoModules() ([]string, error) {
	return topGoModules, nil
}

// FetchNpmPackages fetches popular npm packages from the registry search API.
func FetchNpmPackages() ([]string, error) {
	url := "https://registry.npmjs.org/-/v1/search?text=&size=500&sort=popularity"

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("npm registry request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read npm response: %w", err)
	}

	var result struct {
		Objects []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"objects"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse npm response: %w", err)
	}

	names := make([]string, 0, len(result.Objects))
	for _, obj := range result.Objects {
		if obj.Package.Name != "" {
			names = append(names, obj.Package.Name)
		}
	}

	return names, nil
}

// EnsurePopularPackages loads from cache, refreshing if expired.
func EnsurePopularPackages() (*PopularPackages, error) {
	cached, err := LoadPopularPackages()
	if err != nil {
		return nil, err
	}

	// Cache is valid and fresh
	if len(cached.GoModules) > 0 && len(cached.NpmPackages) > 0 {
		return cached, nil
	}

	// Fetch fresh data
	pkgs := &PopularPackages{}

	goModules, err := FetchGoModules()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Go modules: %w", err)
	}
	pkgs.GoModules = goModules

	npmPackages, err := FetchNpmPackages()
	if err != nil {
		// npm fetch is non-fatal; use empty list
		pkgs.NpmPackages = []string{}
	} else {
		pkgs.NpmPackages = npmPackages
	}

	sort.Strings(pkgs.GoModules)
	sort.Strings(pkgs.NpmPackages)

	// Save to cache (best-effort, don't fail the scan)
	_ = SavePopularPackages(pkgs)

	return pkgs, nil
}
