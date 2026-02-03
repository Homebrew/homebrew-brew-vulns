# frozen_string_literal: true

require_relative "lib/brew/vulns/version"

Gem::Specification.new do |spec|
  spec.name = "brew-vulns"
  spec.version = Brew::Vulns::VERSION
  spec.authors = ["Andrew Nesbitt"]
  spec.email = ["andrewnez@gmail.com"]

  spec.summary = "Check Homebrew packages for known vulnerabilities"
  spec.description = "A Homebrew subcommand that checks installed packages for vulnerabilities via osv.dev"
  spec.homepage = "https://github.com/homebrew/brew-vulns"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/ .github/])
    end
  end
  spec.bindir = "exe"
  spec.executables = ["brew-vulns"]
  spec.require_paths = ["lib"]

  spec.add_dependency "purl", "~> 1.6"
  spec.add_dependency "sarif-ruby", "~> 0.1"
  spec.add_dependency "sbom", "~> 0.4"
  spec.add_dependency "vers", "~> 1.0"
end
