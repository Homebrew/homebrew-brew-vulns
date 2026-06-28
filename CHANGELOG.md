## [Unreleased]

- Query OSV for formulae whose source is not on GitHub/GitLab/Codeberg by falling back to the formula's `head` git URL, a `tag:`-style stable git URL, or a forge URL in `homepage`, with the bare formula version. Removes the forge whitelist; any formula with a derivable git repository URL is now sent in the batch query

## [0.4.0] - 2026-06-28

- Suppress vulnerabilities that a formula's patches declare as resolved (via `patches[].resolves` in `brew info --json=v2`, Homebrew 6.0.4+); list them separately in text/JSON output, exclude them from SARIF output, and exclude them from the exit code
- CycloneDX output: emit patched vulnerabilities with `analysis.state = resolved` and include formula patches as `pedigree.patches` on each component
- Add `--no-ignore-patches` to report patched vulnerabilities as open findings
- Fix invalid SARIF output when no vulnerabilities are found (GitHub code scanning rejected the file)

## [0.3.0] - 2026-05-29

- Add `--all` flag to scan every formula in homebrew-core
- Accept one or more formula names as arguments to scan specific formulae, including ones that are not installed
- Exit with status 2 on errors so callers can distinguish errors from "vulnerabilities found" (exit 1)
- Add example GitHub Actions workflows for tap PR checks and full homebrew-core scans
- Compute severity bands from CVSS vector strings when OSV data does not provide a severity label
- Improve CVSS severity fallback handling when multiple score sources are present
- Handle unbounded `introduced: 0` OSV ranges and multi-interval SEMVER ranges correctly
- Fail closed (report as affected) when a version range comparison raises instead of silently skipping
- Sanitize ANSI/terminal escape sequences, carriage returns and backspaces from text output
- Cap concurrent requests when fetching vulnerability details to avoid unbounded thread spawning
- Cap OSV pagination at a fixed page limit to avoid unbounded loops on bad responses
- Set a `User-Agent` header on OSV API requests

## [0.2.3] - 2026-02-05

- Move repository to the Homebrew organisation and update install instructions, formula and links accordingly
- Internal: shared CI/lint configuration sync and dependency updates

## [0.2.2] - 2026-01-25

- Add retry logic to OSV API requests (up to 3 attempts on timeout or connection errors)

## [0.2.1] - 2026-01-08

- Fix severity extraction for OSS-Fuzz vulnerabilities by reading `ecosystem_specific.severity` from OSV data

## [0.2.0] - 2026-01-08

- Add CycloneDX SBOM output with vulnerabilities (`--cyclonedx`)
- Add Brewfile scanning support (`--brewfile`) to check packages from a Brewfile
- Add SARIF output for GitHub code scanning integration (`--sarif`)
- Add severity filtering to only show vulnerabilities at or above a threshold (`--severity`)
- Add configurable summary truncation length (`--max-summary`)
- Fetch vulnerability details in parallel for faster scans
- Add GitLab and Codeberg support alongside GitHub
- Log warnings when version parsing fails instead of silently ignoring errors

## [0.1.0] - 2026-01-08

- Initial release
