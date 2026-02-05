class BrewVulns < Formula
  desc "Check Homebrew packages for known vulnerabilities via osv.dev"
  homepage "https://github.com/Homebrew/homebrew-brew-vulns"
  url "https://github.com/Homebrew/homebrew-brew-vulns/archive/refs/tags/v0.2.3.tar.gz"
  sha256 "1f1bdc60daeeded30d22026ba80e66854a95a299f92392c8624997b75d0f971e"
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
