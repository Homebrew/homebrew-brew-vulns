# frozen_string_literal: true

module Brew
  module Vulns
    class CLI
      def self.run(args)
        new(args).run
      end

      DEFAULT_MAX_SUMMARY = 60
      SEVERITY_LEVELS = { "low" => 1, "medium" => 2, "high" => 3, "critical" => 4 }.freeze

      def initialize(args)
        @args = args
        @formula_filter = args.first unless args.first&.start_with?("-")
        @include_deps = args.include?("--deps") || args.include?("-d")
        @json_output = args.include?("--json") || args.include?("-j")
        @sarif_output = args.include?("--sarif")
        @help = args.include?("--help") || args.include?("-h")
        @max_summary = parse_max_summary(args)
        @min_severity = parse_severity(args)
        @brewfile = parse_brewfile_path(args)
      end

      def parse_max_summary(args)
        args.each_with_index do |arg, idx|
          if arg == "--max-summary" || arg == "-m"
            value = args[idx + 1]
            return value.to_i if value && !value.start_with?("-")
          elsif arg.start_with?("--max-summary=")
            return arg.split("=", 2).last.to_i
          end
        end
        DEFAULT_MAX_SUMMARY
      end

      def parse_severity(args)
        args.each_with_index do |arg, idx|
          if arg == "--severity" || arg == "-s"
            value = args[idx + 1]
            return SEVERITY_LEVELS[value&.downcase] || 0 if value && !value.start_with?("-")
          elsif arg.start_with?("--severity=")
            value = arg.split("=", 2).last
            return SEVERITY_LEVELS[value&.downcase] || 0
          end
        end
        0
      end

      def parse_brewfile_path(args)
        args.each_with_index do |arg, idx|
          if arg == "--brewfile" || arg == "-b"
            value = args[idx + 1]
            return value if value && !value.start_with?("-")
            return "Brewfile"
          elsif arg.start_with?("--brewfile=")
            return arg.split("=", 2).last
          end
        end
        nil
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

        unless @json_output || @sarif_output
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
        if @brewfile
          Formula.load_from_brewfile(@brewfile, include_deps: @include_deps)
        elsif @include_deps && @formula_filter
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

          threads = batch_vulns.map do |v|
            Thread.new { client.get_vulnerability(v["id"]) }
          end
          full_vulns = threads.map(&:value)
          vulns = Vulnerability.from_osv_list(full_vulns)

          version = formula.tag || formula.version
          vulns = vulns.select { |v| v.affects_version?(version) }
          vulns = vulns.select { |v| v.severity_level >= @min_severity } if @min_severity > 0

          results[formula] = vulns if vulns.any?
        end

        results
      end

      def output_results(results, all_formulae)
        if @sarif_output
          output_sarif(results)
        elsif @json_output
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

      def output_sarif(results)
        rules = []
        sarif_results = []

        results.each do |formula, vulns|
          vulns.each do |vuln|
            rule_id = vuln.id
            rules << Sarif::ReportingDescriptor.new(
              id: rule_id,
              name: rule_id,
              short_description: Sarif::MultiformatMessageString.new(
                text: vuln.summary || "Security vulnerability"
              ),
              help_uri: vuln.advisory_url,
              default_configuration: Sarif::ReportingConfiguration.new(
                level: sarif_level(vuln.severity_display)
              )
            )

            sarif_results << Sarif::Result.new(
              rule_id: rule_id,
              level: sarif_level(vuln.severity_display),
              message: Sarif::Message.new(
                text: "#{formula.name}@#{formula.version}: #{vuln.summary || vuln.id}"
              ),
              locations: [
                Sarif::Location.new(
                  physical_location: Sarif::PhysicalLocation.new(
                    artifact_location: Sarif::ArtifactLocation.new(
                      uri: formula.repo_url || formula.name
                    )
                  ),
                  message: Sarif::Message.new(
                    text: "Affected package: #{formula.name} version #{formula.version}"
                  )
                )
              ]
            )
          end
        end

        log = Sarif::Log.new(
          version: "2.1.0",
          runs: [
            Sarif::Run.new(
              tool: Sarif::Tool.new(
                driver: Sarif::ToolComponent.new(
                  name: "brew-vulns",
                  version: VERSION,
                  information_uri: "https://github.com/andrew/brew-vulns",
                  rules: rules.uniq { |r| r.id }
                )
              ),
              results: sarif_results
            )
          ]
        )

        puts JSON.pretty_generate(log.to_h)
        results.empty? ? 0 : 1
      end

      def sarif_level(severity)
        case severity&.downcase
        when "critical", "high" then "error"
        when "medium" then "warning"
        when "low" then "note"
        else "warning"
        end
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
              summary = if @max_summary > 0 && vuln.summary.length > @max_summary
                "#{vuln.summary.slice(0, @max_summary)}..."
              else
                vuln.summary
              end
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
            formula              Check only this formula (optional)

          Options:
            -b, --brewfile PATH  Scan packages from a Brewfile (default: ./Brewfile)
            -d, --deps           Include dependencies when checking a specific formula or Brewfile
            -j, --json           Output results as JSON
            --sarif              Output results as SARIF for GitHub code scanning
            -m, --max-summary N  Truncate summaries to N characters (default: 60, 0 for no limit)
            -s, --severity LEVEL Only show vulnerabilities at or above LEVEL (low, medium, high, critical)
            -h, --help           Show this help message

          Examples:
            brew vulns                    Check all installed packages
            brew vulns openssl            Check only openssl
            brew vulns vim --deps         Check vim and its dependencies
            brew vulns --brewfile         Scan packages listed in ./Brewfile
            brew vulns -b ~/project/Brewfile  Scan a specific Brewfile
            brew vulns -b Brewfile --deps Scan Brewfile packages and their dependencies
            brew vulns --json             Output as JSON for CI/CD
            brew vulns --sarif            Output as SARIF for GitHub Actions
            brew vulns --severity high    Only show HIGH and CRITICAL vulnerabilities
        HELP
      end
    end
  end
end
