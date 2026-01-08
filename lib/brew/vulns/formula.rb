# frozen_string_literal: true

require "json"
require "open3"

module Brew
  module Vulns
    class Formula
      attr_reader :name, :version, :source_url, :head_url, :dependencies

      def initialize(data)
        @name = data["name"] || data["full_name"]
        @version = data.dig("versions", "stable") || data["version"]
        @source_url = data.dig("urls", "stable", "url")
        @head_url = data.dig("urls", "head", "url")
        @dependencies = data["dependencies"] || []
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

      def self.load_installed(formula_filter = nil)
        json, status = Open3.capture2("brew", "info", "--json=v2", "--installed")
        raise Error, "brew info failed with status #{status.exitstatus}" unless status.success?

        data = JSON.parse(json)
        formulae = data["formulae"].map { |f| new(f) }

        if formula_filter
          formulae.select! { |f| f.name == formula_filter || f.name.start_with?("#{formula_filter}@") }
        end

        formulae
      end

      def self.load_with_dependencies(formula_filter = nil)
        json, status = Open3.capture2("brew", "info", "--json=v2", "--installed")
        raise Error, "brew info failed with status #{status.exitstatus}" unless status.success?

        data = JSON.parse(json)
        all_formulae = data["formulae"].map { |f| new(f) }
        formulae_by_name = all_formulae.each_with_object({}) { |f, h| h[f.name] = f }

        if formula_filter
          filtered = all_formulae.select { |f| f.name == formula_filter || f.name.start_with?("#{formula_filter}@") }
          return [] if filtered.empty?

          deps_output, = Open3.capture2("brew", "deps", "--installed", formula_filter)
          dep_names = deps_output.split("\n").map(&:strip)

          result = filtered.each_with_object({}) { |f, h| h[f.name] = f }
          dep_names.each do |dep_name|
            dep = formulae_by_name[dep_name]
            result[dep_name] = dep if dep && !result[dep_name]
          end

          result.values
        else
          all_formulae
        end
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
