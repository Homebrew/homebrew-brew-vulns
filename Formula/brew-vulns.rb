class BrewVulns < Formula
  desc "Check Homebrew packages for known vulnerabilities via osv.dev"
  homepage "https://github.com/homebrew/brew-vulns"
  url "https://github.com/homebrew/brew-vulns/archive/refs/tags/v0.2.2.tar.gz"
  sha256 "64abf7791eb7d04312c1fda9dc49a73f3702f5716ce18506324ed9f401fe2514"
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
