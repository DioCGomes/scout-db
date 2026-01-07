# Scout DB

SQLite databases of security advisories extracted from the [GitHub Advisory Database](https://github.com/github/advisory-database) to run on SCA Tool [Scout](https://github.com/mlw157/scout).

## Databases

| Database | Description | Download |
|----------|-------------|----------|
| `scout.db` | All vulnerabilities (reviewed + unreviewed) | [Latest](https://github.com/DioCGomes/scout-db/releases/latest/download/scout.db) |
| `scout-reviewed.db` | GitHub-reviewed vulnerabilities only | [Latest](https://github.com/DioCGomes/scout-db/releases/latest/download/scout-reviewed.db) |

## Download

### Latest Release

```bash
# Download all vulnerabilities
curl -LO https://github.com/mlw157/scout-db/releases/latest/download/scout.db

# Download reviewed only
curl -LO https://github.com/mlw157/scout-db/releases/latest/download/scout-reviewed.db
```

### Using Make

```bash
make download          # Download both databases
make download-reviewed # Download reviewed only
make download-all      # Download all vulnerabilities only
```

## Local Development

### Prerequisites

- Python 3.11+
- Git
- Make

### Build Locally

```bash
# Clone this repo
git clone https://github.com/DioCGomes/scout-db.git
cd scout-db

# Clone the GitHub Advisory Database
make clone

# Build both databases
make build

# Or do everything in one step
make all
```

### Makefile Commands

| Command | Description |
|---------|-------------|
| `make clone` | Clone the GitHub Advisory Database |
| `make build` | Build both SQLite databases |
| `make all` | Clone and build (full setup) |
| `make download` | Download latest databases from releases |
| `make download-reviewed` | Download only reviewed database |
| `make download-all` | Download only all-vulns database |
| `make clean` | Remove generated databases |
| `make clean-all` | Remove databases and cloned advisory repo |

## Database Schema

```sql
CREATE TABLE advisories (
    id TEXT PRIMARY KEY,
    package TEXT,
    version_range TEXT,
    first_patched_version TEXT,
    ecosystem TEXT,
    severity TEXT,
    summary TEXT,
    details TEXT,
    cve TEXT,
    "references" TEXT
);
```

### Supported Ecosystems

- `npm` - Node.js
- `pip` - Python (PyPI)
- `maven` - Java
- `gem` - Ruby (RubyGems)
- `composer` - PHP (Packagist)
- `go` - Go modules
- `cargo` - Rust (crates.io)

## Query Examples

```bash
# Count advisories by ecosystem
sqlite3 scout.db "SELECT ecosystem, COUNT(*) FROM advisories GROUP BY ecosystem ORDER BY COUNT(*) DESC;"

# Find vulnerabilities for a specific package
sqlite3 scout.db "SELECT id, severity, version_range FROM advisories WHERE package = 'lodash';"

# List critical vulnerabilities
sqlite3 scout.db "SELECT id, package, ecosystem FROM advisories WHERE severity LIKE '%CRITICAL%';"
```

## Automated Updates

The databases are automatically rebuilt weekly (Sundays at midnight UTC) via GitHub Actions and published as releases. Only the last 5 releases are retained.
