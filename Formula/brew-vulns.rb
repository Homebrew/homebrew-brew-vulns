class BrewVulns < Formula
  desc "Check Homebrew packages for known vulnerabilities via osv.dev"
  homepage "https://github.com/Homebrew/homebrew-brew-vulns"
  url "https://github.com/Homebrew/homebrew-brew-vulns/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "1b9fbb03d46192350ad7dcac4279b382debb917d40688a4b816319214a2570d4"
  license "MIT"

  depends_on "ruby"

  def install
    ENV["GEM_HOME"] = libexec

    system "git", "init"
    system "git", "add", "."

    system "gem", "build", "brew-vulns.gemspec"
    system "gem", "install", "--no-document", "brew-vulns-#{version}.gem"
    bin.install libexec/"bin/brew-vulns"
    bin.env_script_all_files(libexec/"bin", GEM_HOME: ENV.fetch("GEM_HOME", nil))
  end

  test do
    system bin/"brew-vulns", "--help"
  end
end
