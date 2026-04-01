# depscan

🔍 **Supply Chain Security Scanner** - Scan Go, Node.js, and Python dependencies for known vulnerabilities.

## Features

- ✅ Scan Go modules (go.mod)
- ✅ Scan NPM packages (package-lock.json)
- ✅ Scan PNPM packages (pnpm-lock.yaml)
- ✅ Scan UV Python packages (uv.lock)
- ✅ Query OSV.dev vulnerability database
- ✅ Risk scoring (0-100)
- ✅ Colorized terminal output
- ✅ JSON export for scripting

## Installation

```bash
make build
```

Or manually:
```bash
go build -o depscan .
```

## Usage

### Basic Scan
```bash
# Scan current directory
depscan .

# Scan specific project
depscan ./myproject
```

### JSON Output
```bash
# Save report to JSON
depscan ./myproject -o report.json
```

### Help
```bash
depscan --help
depscan --version
```

## Example Output

```
🔍 Scanning dependencies in: ./myproject

📦 Found 12 Go modules, 8 NPM/PNPM packages, 5 UV packages

📦 github.com/gin-gonic/gin@1.9.0 [Go]
   ❌ GHSA-xxxx-xxxx-xxxx [HIGH] Path traversal vulnerability...

──────────────────────────────────────────────────
📊 Summary
──────────────────────────────────────────────────
   Vulnerabilities: 3
   Risk Score: 65/100 [HIGH]

❌ Action required: Fix vulnerabilities before deploying!
```

## JSON Output Format

```json
{
  "scan_time": "2026-03-17T23:30:00Z",
  "project_path": "./myproject",
  "total_dependencies": 20,
  "vulnerabilities_found": 3,
  "risk_score": 65,
  "risk_level": "HIGH",
  "results": [
    {
      "package": "github.com/gin-gonic/gin",
      "version": "1.9.0",
      "ecosystem": "Go",
      "vulnerabilities": [
        {
          "id": "GHSA-xxxx-xxxx-xxxx",
          "severity": "HIGH",
          "summary": "Path traversal vulnerability"
        }
      ]
    }
  ]
}
```

## Risk Scoring

| Severity | Points |
|----------|--------|
| CRITICAL | 30 |
| HIGH | 20 |
| MEDIUM | 10 |
| LOW | 5 |

Score is capped at 100.

## Tech Stack

- **Language**: Go 1.22
- **CLI Framework**: Cobra
- **Colors**: fatih/color
- **CVE Database**: OSV.dev API

## Development

| Command | Description |
|---------|-------------|
| `make build` | Build the binary |
| `make run` | Run the application |
| `make test` | Run tests |
| `make fmt` | Format code |
| `make lint` | Run linter |
| `make clean` | Remove build artifacts |
| `make install` | Install to GOPATH/bin |

## Roadmap

- [ ] SARIF output for CI/CD
- [ ] Private registry support
- [ ] SBOM generation
- [ ] Auto-fix suggestions

## License

MIT

## Author

Built by jasonli0226
