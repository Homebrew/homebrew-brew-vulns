# Example workflows

GitHub Actions workflows showing how `brew vulns` can be wired into a Homebrew tap.

`pr-vuln-check.yml` runs on pull requests that touch `Formula/**/*.rb`. It works out which formulae changed, runs `brew vulns <names> --sarif` against them, and uploads the result to GitHub code scanning so vulnerabilities appear as annotations on the PR.

`scan-all.yml` runs daily, scans every formula in homebrew-core with `brew vulns --all --json`, and publishes `vulns.json` as an asset on a rolling `vulns` release. Downstream tooling (including Homebrew itself) can fetch that file rather than querying OSV directly.

Copy whichever you need into `.github/workflows/` in the target repository and adjust to taste.
