class BrewVulns < Formula
  desc "Check Homebrew packages for known vulnerabilities via osv.dev"
  homepage "https://github.com/Homebrew/homebrew-brew-vulns"
  url "https://github.com/Homebrew/homebrew-brew-vulns/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  deprecate! date: "2026-07-14", because: "is now built into Homebrew as `brew vulns`"

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

  def caveats
    <<~EOS
      `brew vulns` is now a built-in Homebrew command. Run `brew update` and
      use `brew vulns` directly, then `brew uninstall brew-vulns` and
      `brew untap homebrew/brew-vulns`.
    EOS
  end

  test do
    system bin/"brew-vulns", "--help"
  end
end
