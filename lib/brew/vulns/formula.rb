# frozen_string_literal: true

require "json"
require "open3"

module Brew
  module Vulns
    class Formula
      attr_reader :name, :version, :source_url, :head_url, :dependencies, :patches

      def initialize(data)
        @name = data["name"] || data["full_name"]
        @version = data.dig("versions", "stable") || data["version"]
        @source_url = data.dig("urls", "stable", "url")
        @head_url = data.dig("urls", "head", "url")
        @dependencies = data["dependencies"] || []
        @patches = data["patches"] || []
      end

      # CVE/GHSA identifiers declared as resolved by this formula's patches.
      # Populated from `brew info --json=v2` `patches[].resolves[]` (Homebrew >= 6.0.4);
      # empty on older Homebrew versions or for formulae with no annotated patches.
      def resolved_vulnerability_ids
        return @resolved_vulnerability_ids if defined?(@resolved_vulnerability_ids)

        @resolved_vulnerability_ids = patches
          .flat_map { |p| Array(p["resolves"]) }
          .select { |r| r.is_a?(Hash) && r["type"] == "security" }
          .map { |r| r["id"].to_s.upcase }
          .uniq
      end

      def resolves?(vulnerability)
        ids = resolved_vulnerability_ids
        return false if ids.empty?

        vulnerability.identifiers.any? { |id| ids.include?(id.to_s.upcase) }
      end

      def repo_url
        return @repo_url if defined?(@repo_url)

        @repo_url = extract_repo_url(source_url) || extract_repo_url(head_url)
      end

      def tag
        return @tag if defined?(@tag)

        @tag = extract_tag_from_url(source_url)
      end

      def github?
        repo_url&.include?("github.com")
      end

      def gitlab?
        repo_url&.include?("gitlab.com")
      end

      def codeberg?
        repo_url&.include?("codeberg.org")
      end

      def supported_forge?
        github? || gitlab? || codeberg?
      end

      def to_osv_query
        return nil unless repo_url && tag

        { repo_url: repo_url, version: tag, name: name }
      end

      def self.load_all
        json, status = Open3.capture2("brew", "info", "--json=v2", "--eval-all")
        raise Error, "brew info failed with status #{status.exitstatus}" unless status.success?

        data = JSON.parse(json)
        data["formulae"].map { |f| new(f) }
      end

      def self.load_installed
        json, status = Open3.capture2("brew", "info", "--json=v2", "--installed")
        raise Error, "brew info failed with status #{status.exitstatus}" unless status.success?

        data = JSON.parse(json)
        data["formulae"].map { |f| new(f) }
      end

      def self.load_named(formula_names, include_deps: false)
        return [] if formula_names.empty?

        json, status = Open3.capture2("brew", "info", "--json=v2", *formula_names)
        raise Error, "brew info failed with status #{status.exitstatus}" unless status.success?

        data = JSON.parse(json)
        formulae = data["formulae"].map { |f| new(f) }

        if include_deps
          dep_names = []
          formula_names.each do |name|
            deps_output, = Open3.capture2("brew", "deps", name)
            dep_names.concat(deps_output.split("\n").map(&:strip))
          end
          dep_names.uniq!
          dep_names -= formula_names

          if dep_names.any?
            deps_json, deps_status = Open3.capture2("brew", "info", "--json=v2", *dep_names)
            if deps_status.success?
              deps_data = JSON.parse(deps_json)
              formulae.concat(deps_data["formulae"].map { |f| new(f) })
            end
          end
        end

        formulae.uniq { |f| f.name }
      end

      def self.load_from_brewfile(brewfile_path, include_deps: false)
        raise Error, "Brewfile not found: #{brewfile_path}" unless File.exist?(brewfile_path)

        formula_names = parse_brewfile(brewfile_path)
        load_named(formula_names, include_deps: include_deps)
      end

      def self.parse_brewfile(brewfile_path)
        output, status = Open3.capture2("brew", "bundle", "list", "--file=#{brewfile_path}", "--formula")
        raise Error, "brew bundle list failed with status #{status.exitstatus}" unless status.success?

        output.split("\n").map(&:strip).reject(&:empty?)
      end

      private

      def extract_repo_url(url)
        return nil unless url

        forges = %w[github.com gitlab.com codeberg.org]
        forge = forges.find { |f| url.include?(f) }
        return nil unless forge

        match = url.match(%r{https?://#{Regexp.escape(forge)}/([^/]+/[^/]+)})
        if match
          repo_path = match[1].sub(/\.git$/, "").sub(%r{/-/.*}, "")
          return "https://#{forge}/#{repo_path}"
        end

        nil
      end

      def extract_tag_from_url(url)
        return nil unless url

        patterns = [
          %r{/archive/refs/tags/([^/]+)\.tar\.gz$},
          %r{/archive/refs/tags/([^/]+)\.zip$},
          %r{/archive/([^/]+)\.tar\.gz$},
          %r{/archive/([^/]+)\.zip$},
          %r{/releases/download/([^/]+)/},
          %r{/tarball/([^/]+)$}
        ]

        patterns.each do |pattern|
          match = url.match(pattern)
          return match[1] if match
        end

        nil
      end
    end
  end
end
