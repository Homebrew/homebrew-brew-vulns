# brew-vulns

A Homebrew subcommand that checks installed packages for known vulnerabilities using the [OSV.dev](https://osv.dev) database.

## Installation

Via Homebrew:

```bash
brew tap andrew/brew-vulns https://github.com/andrew/brew-vulns
brew install brew-vulns
```

Or via RubyGems:

```bash
gem install brew-vulns
```

Once installed, the command is available as `brew vulns`.

## Usage

```bash
brew vulns [formula] [options]
```

### Options

| Flag | Long form | Description |
|------|-----------|-------------|
| `-b PATH` | `--brewfile PATH` | Scan packages from a Brewfile (default: ./Brewfile) |
| `-d` | `--deps` | Include dependencies when checking a specific formula or Brewfile |
| `-j` | `--json` | Output results as JSON |
| | `--sarif` | Output results as SARIF for GitHub code scanning |
| `-m N` | `--max-summary N` | Truncate summaries to N characters (default: 60, 0 for no limit) |
| `-s LEVEL` | `--severity LEVEL` | Only show vulnerabilities at or above LEVEL (low, medium, high, critical) |
| `-h` | `--help` | Show help message |

### Examples

```bash
# Check all installed packages
brew vulns

# Check a specific formula
brew vulns openssl

# Check a formula and its dependencies
brew vulns python --deps

# Scan packages from a Brewfile
brew vulns --brewfile

# Scan a specific Brewfile
brew vulns -b ~/project/Brewfile

# Scan Brewfile packages and their dependencies
brew vulns --brewfile --deps

# Output as JSON (useful for CI/CD)
brew vulns --json

# Show longer summaries
brew vulns --max-summary 100

# Show full summaries (no truncation)
brew vulns -m 0

# Only show HIGH and CRITICAL vulnerabilities
brew vulns --severity high

# Output as SARIF for GitHub code scanning
brew vulns --sarif > results.sarif

# Show help
brew vulns --help
```

## How it works

1. Reads installed Homebrew formulae via `brew info --json=v2 --installed`
2. Extracts the repository URL and version tag from each formula's source URL
3. Queries the OSV API using the GIT ecosystem to find known vulnerabilities
4. Reports any vulnerabilities found with their severity and CVE identifiers

Packages with GitHub, GitLab, or Codeberg source URLs are checked. Packages from other sources are skipped.

## Example output

```
Checking 104 packages for vulnerabilities...
(119 packages skipped - no supported source URL)

expat (2.7.3)
  CVE-2025-66382 (HIGH) - XML parsing vulnerability...

hdf5 (1.14.6)
  OSV-2023-1091 (MEDIUM) - Buffer overflow in...
  OSV-2023-1223 (MEDIUM) - ...

Found 15 vulnerabilities in 3 packages
```

## Exit codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities found (or error occurred)

This makes it suitable for use in CI/CD pipelines.

## GitHub Actions

Use the `--sarif` flag to integrate with GitHub code scanning:

```yaml
name: Vulnerability Scan

on:
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:

jobs:
  scan:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install brew-vulns
        run: gem install brew-vulns

      - name: Run vulnerability scan
        run: brew vulns --sarif > results.sarif
        continue-on-error: true

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Development

```bash
git clone https://github.com/andrewnesbitt/brew-vulns
cd brew-vulns
bin/setup
rake test
```

## License

MIT License. See [LICENSE](LICENSE) for details.
