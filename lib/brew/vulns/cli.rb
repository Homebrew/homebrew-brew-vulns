# frozen_string_literal: true

module Brew
  module Vulns
    class CLI
      def self.run(args)
        new(args).run
      end

      def initialize(args)
        @args = args
        @formula_filter = args.first unless args.first&.start_with?("-")
        @include_deps = args.include?("--deps") || args.include?("-d")
        @json_output = args.include?("--json") || args.include?("-j")
        @help = args.include?("--help") || args.include?("-h")
      end

      def run
        if @help
          print_help
          return 0
        end

        formulae = load_formulae
        if formulae.empty?
          puts "No installed formulae found."
          return 0
        end

        queryable = formulae.select(&:supported_forge?).select(&:tag)
        skipped = formulae.size - queryable.size

        unless @json_output
          puts "Checking #{queryable.size} packages for vulnerabilities..."
          puts "(#{skipped} packages skipped - no supported source URL)" if skipped > 0
          puts
        end

        results = scan_vulnerabilities(queryable)
        output_results(results, formulae)
      rescue OsvClient::Error => e
        $stderr.puts "Error querying OSV: #{e.message}"
        1
      rescue Error => e
        $stderr.puts "Error: #{e.message}"
        1
      rescue JSON::ParserError => e
        $stderr.puts "Error parsing brew output: #{e.message}"
        1
      end

      private

      def load_formulae
        if @include_deps && @formula_filter
          Formula.load_with_dependencies(@formula_filter)
        else
          Formula.load_installed(@formula_filter)
        end
      end

      def scan_vulnerabilities(formulae)
        client = OsvClient.new
        queries = formulae.map(&:to_osv_query).compact

        vuln_results = client.query_batch(queries)

        results = {}
        formulae.each_with_index do |formula, idx|
          batch_vulns = vuln_results[idx] || []
          next if batch_vulns.empty?

          full_vulns = batch_vulns.map { |v| client.get_vulnerability(v["id"]) }
          vulns = Vulnerability.from_osv_list(full_vulns)

          version = formula.tag || formula.version
          vulns = vulns.select { |v| v.affects_version?(version) }

          results[formula] = vulns if vulns.any?
        end

        results
      end

      def output_results(results, all_formulae)
        if @json_output
          output_json(results)
        else
          output_text(results, all_formulae)
        end
      end

      def output_json(results)
        data = results.map do |formula, vulns|
          {
            formula: formula.name,
            version: formula.version,
            tag: formula.tag,
            repo_url: formula.repo_url,
            vulnerabilities: vulns.map do |v|
              {
                id: v.id,
                severity: v.severity_display,
                summary: v.summary,
                aliases: v.aliases,
                fixed_versions: v.fixed_versions
              }
            end
          }
        end

        puts JSON.pretty_generate(data)
        results.empty? ? 0 : 1
      end

      def output_text(results, all_formulae)
        if results.empty?
          puts "No vulnerabilities found."
          return 0
        end

        total_vulns = 0
        sorted = results.sort_by { |_, vulns| -vulns.map(&:severity_level).max }

        sorted.each do |formula, vulns|
          puts "#{formula.name} (#{formula.version})"
          vulns.sort_by { |v| -v.severity_level }.each do |vuln|
            total_vulns += 1
            severity = colorize_severity(vuln.severity_display)

            line = "  #{vuln.id} (#{severity})"
            if vuln.summary
              summary = vuln.summary.length > 60 ? "#{vuln.summary.slice(0, 60)}..." : vuln.summary
              line = "#{line} - #{summary}"
            end
            puts line

            if vuln.fixed_versions.any?
              puts "    Fixed in: #{vuln.fixed_versions.join(", ")}"
            end
          end
          puts
        end

        puts "Found #{total_vulns} vulnerabilities in #{results.size} packages"
        1
      end

      def colorize_severity(severity)
        return severity unless $stdout.tty?

        case severity
        when "CRITICAL" then "\e[1;31m#{severity}\e[0m"
        when "HIGH" then "\e[31m#{severity}\e[0m"
        when "MEDIUM" then "\e[33m#{severity}\e[0m"
        when "LOW" then "\e[32m#{severity}\e[0m"
        else severity
        end
      end

      def print_help
        puts <<~HELP
          Usage: brew vulns [formula] [options]

          Check installed Homebrew packages for known vulnerabilities via osv.dev.

          Arguments:
            formula          Check only this formula (optional)

          Options:
            -d, --deps       Include dependencies when checking a specific formula
            -j, --json       Output results as JSON
            -h, --help       Show this help message

          Examples:
            brew vulns                    Check all installed packages
            brew vulns openssl            Check only openssl
            brew vulns vim --deps         Check vim and its dependencies
            brew vulns --json             Output as JSON for CI/CD
        HELP
      end
    end
  end
end
