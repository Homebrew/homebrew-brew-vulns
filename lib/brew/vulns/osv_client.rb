# frozen_string_literal: true

require "net/http"
require "json"
require "uri"
require "brew/vulns/version"

module Brew
  module Vulns
    class OsvClient
      API_BASE = "https://api.osv.dev/v1"
      BATCH_SIZE = 1000
      OPEN_TIMEOUT = 10
      READ_TIMEOUT = 30
      MAX_RETRIES = 3
      RETRY_DELAY = 1

      # Sent alongside each real query. OSV's normalize_tag extracts digit-runs;
      # digit-free strings collapse to "" and fuzzy-match any digit-free tag in
      # an affected range (e.g. "last-cvs-commit"). If real and canary return
      # identical non-empty sets, the real tag hit the same degenerate match.
      # See issue #41 and google/osv.dev gcp/api/server.py:_match_versions.
      CANARY_VERSION = "brew-vulns-canary"

      class Error < StandardError; end
      class ApiError < Error; end

      USER_AGENT = "brew-vulns/#{Brew::Vulns::VERSION} (+https://github.com/Homebrew/homebrew-brew-vulns)"

      def query(repo_url:, version:)
        payload = {
          package: {
            name: repo_url,
            ecosystem: "GIT"
          },
          version: version
        }

        response = post("/query", payload)
        fetch_all_pages(response, payload)
      end

      def query_batch(packages)
        return [] if packages.empty?

        results = Array.new(packages.size) { [] }
        # Worst case every version is digit-free and gets a canary, so slice at
        # half the limit to guarantee queries.size <= BATCH_SIZE.
        slice_size = BATCH_SIZE / 2

        packages.each_slice(slice_size).with_index do |batch, batch_idx|
          queries = []
          offsets = []
          batch.each do |pkg|
            package_ref = { name: pkg[:repo_url], ecosystem: "GIT" }
            real_idx = queries.size
            queries << { package: package_ref, version: pkg[:version] }
            canary_idx = nil
            unless pkg[:version].to_s.match?(/\d/)
              canary_idx = queries.size
              queries << { package: package_ref, version: CANARY_VERSION }
            end
            offsets << [real_idx, canary_idx]
          end

          response = post("/querybatch", { queries: queries })
          batch_results = response["results"] || []

          batch.each_with_index do |pkg, idx|
            global_idx = batch_idx * slice_size + idx
            real_idx, canary_idx = offsets[idx]
            real = batch_results[real_idx] || {}
            results[global_idx] = real["vulns"] || []
            next unless canary_idx

            canary = batch_results[canary_idx] || {}
            real_ids   = results[global_idx].map { |v| v["id"] }.sort
            canary_ids = (canary["vulns"] || []).map { |v| v["id"] }.sort
            next if canary_ids.empty? || real_ids != canary_ids

            warn "Warning: OSV could not resolve #{pkg[:name] || pkg[:repo_url]} " \
                 "tag #{pkg[:version].inspect}; skipping (results matched " \
                 "default-branch fallback)"
            results[global_idx] = []
          end
        end

        results
      end

      def get_vulnerability(vuln_id)
        get("/vulns/#{URI.encode_uri_component(vuln_id)}")
      end

      def post(path, payload)
        uri = URI("#{API_BASE}#{path}")
        request = Net::HTTP::Post.new(uri)
        request["Content-Type"] = "application/json"
        request["User-Agent"] = USER_AGENT
        request.body = JSON.generate(payload)

        execute_request(uri, request)
      end

      def get(path)
        uri = URI("#{API_BASE}#{path}")
        request = Net::HTTP::Get.new(uri)
        request["Content-Type"] = "application/json"
        request["User-Agent"] = USER_AGENT

        execute_request(uri, request)
      end

      def execute_request(uri, request)
        attempts = 0

        begin
          attempts += 1
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == "https"
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.open_timeout = OPEN_TIMEOUT
          http.read_timeout = READ_TIMEOUT

          response = http.request(request)

          case response
          when Net::HTTPSuccess
            JSON.parse(response.body)
          else
            raise ApiError, "OSV API error: #{response.code} #{response.message}"
          end
        rescue JSON::ParserError => e
          raise ApiError, "Invalid JSON response from OSV API: #{e.message}"
        rescue Net::OpenTimeout, Net::ReadTimeout => e
          if attempts < MAX_RETRIES
            sleep RETRY_DELAY
            retry
          end
          raise ApiError, "OSV API timeout after #{attempts} attempts: #{e.message}"
        rescue SocketError, Errno::ECONNREFUSED => e
          if attempts < MAX_RETRIES
            sleep RETRY_DELAY
            retry
          end
          raise ApiError, "OSV API connection error after #{attempts} attempts: #{e.message}"
        rescue OpenSSL::SSL::SSLError => e
          raise ApiError, "OSV API SSL error: #{e.message}"
        end
      end

      MAX_PAGES = 100

      def fetch_all_pages(response, original_payload)
        vulns = response["vulns"] || []
        page_token = response["next_page_token"]
        page_count = 1

        while page_token
          if page_count >= MAX_PAGES
            raise ApiError,
                  "OSV API returned more than #{MAX_PAGES} pages of results; aborting to avoid an unbounded loop"
          end

          payload = original_payload.merge(page_token: page_token)
          response = post("/query", payload)
          vulns.concat(response["vulns"] || [])
          page_token = response["next_page_token"]
          page_count += 1
        end

        vulns
      end
    end
  end
end
