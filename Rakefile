# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"
require "digest"
require "open-uri"

Minitest::TestTask.create

task default: :test

desc "Update Formula sha256 hash for current version"
task :update_formula do
  require_relative "lib/brew/vulns/version"

  version = Brew::Vulns::VERSION
  url = "https://github.com/homebrew/brew-vulns/archive/refs/tags/v#{version}.tar.gz"
  formula_path = File.expand_path("Formula/brew-vulns.rb", __dir__)

  puts "Downloading #{url}..."
  tarball = URI.open(url).read
  sha256 = Digest::SHA256.hexdigest(tarball)
  puts "SHA256: #{sha256}"

  formula = File.read(formula_path)
  formula.gsub!(%r{url "https://github.com/homebrew/brew-vulns/archive/refs/tags/v[^"]+\.tar\.gz"},
                "url \"#{url}\"")
  formula.gsub!(/sha256 "[^"]+"/, "sha256 \"#{sha256}\"")
  File.write(formula_path, formula)

  puts "Updated Formula/brew-vulns.rb"
end

Rake::Task["release"].enhance do
  Rake::Task["update_formula"].invoke
end
