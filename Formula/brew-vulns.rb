class BrewVulns < Formula
  desc "Check Homebrew packages for known vulnerabilities via osv.dev"
  homepage "https://github.com/Homebrew/homebrew-brew-vulns"
  url "https://github.com/Homebrew/homebrew-brew-vulns/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "1b9fbb03d46192350ad7dcac4279b382debb917d40688a4b816319214a2570d4"
  license "MIT"

  depends_on "ruby"

  def install
    system "git", "init"
    system "git", "add", "."

    system "gem", "build", "brew-vulns.gemspec"
    system "gem", "install", "--no-document", "--install-dir", libexec,
           "--bindir", libexec/"bin", "brew-vulns-#{version}.gem"

    (bin/"brew-vulns").write <<~BASH
      #!/bin/bash
      #:  * `vulns` [<formula>...] [<options>]
      #:
      #:  Check Homebrew packages for known vulnerabilities via osv.dev.
      #:
      #:  `--all`
      #:    Scan every formula in homebrew-core.
      #:  `-b`, `--brewfile` <path>
      #:    Scan packages from a Brewfile.
      #:  `-d`, `--deps`
      #:    Include dependencies.
      #:  `-j`, `--json`
      #:    Output results as JSON.
      #:  `--cyclonedx`
      #:    Output results as a CycloneDX SBOM.
      #:  `--sarif`
      #:    Output results as SARIF.
      #:  `-m`, `--max-summary` <n>
      #:    Truncate summaries to N characters.
      #:  `-s`, `--severity` <level>
      #:    Only show vulnerabilities at or above LEVEL.
      #:  `-h`, `--help`
      #:    Show this help message.

      export GEM_HOME="#{libexec}"
      export GEM_PATH="#{libexec}"
      exec "#{libexec}/bin/brew-vulns" "$@"
    BASH
    chmod 0755, bin/"brew-vulns"
  end

  test do
    assert_match(/^#:  \* `vulns`/, (bin/"brew-vulns").read)
    assert_match "Usage: brew vulns", shell_output("#{bin}/brew-vulns --help")
  end
end
