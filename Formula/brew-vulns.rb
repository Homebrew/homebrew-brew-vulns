class BrewVulns < Formula
  desc "Check Homebrew packages for known vulnerabilities via osv.dev"
  homepage "https://github.com/andrew/brew-vulns"
  url "https://github.com/andrew/brew-vulns/archive/refs/tags/v0.2.1.tar.gz"
  sha256 "c5952c0337709a79bfcb92a9235920affa0471a8121adedbb8eb763f8b308987"
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
