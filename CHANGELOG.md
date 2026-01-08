## [Unreleased]

## [0.2.0] - 2026-01-08

- Add Brewfile scanning support (`--brewfile`) to check packages from a Brewfile
- Add SARIF output for GitHub code scanning integration (`--sarif`)
- Add severity filtering to only show vulnerabilities at or above a threshold (`--severity`)
- Add configurable summary truncation length (`--max-summary`)
- Fetch vulnerability details in parallel for faster scans
- Add GitLab and Codeberg support alongside GitHub
- Log warnings when version parsing fails instead of silently ignoring errors

## [0.1.0] - 2026-01-08

- Initial release
