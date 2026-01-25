# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module Brew
  module Vulns
    class OsvClient
      API_BASE = "https://api.osv.dev/v1"
      BATCH_SIZE = 1000
      OPEN_TIMEOUT = 10
      READ_TIMEOUT = 30
      MAX_RETRIES = 3
      RETRY_DELAY = 1

      class Error < StandardError; end
      class ApiError < Error; end

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

        packages.each_slice(BATCH_SIZE).with_index do |batch, batch_idx|
          queries = batch.map do |pkg|
            {
              package: {
                name: pkg[:repo_url],
                ecosystem: "GIT"
              },
              version: pkg[:version]
            }
          end

          response = post("/querybatch", { queries: queries })
          batch_results = response["results"] || []

          batch_results.each_with_index do |result, idx|
            global_idx = batch_idx * BATCH_SIZE + idx
            results[global_idx] = result["vulns"] || []
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
        request.body = JSON.generate(payload)

        execute_request(uri, request)
      end

      def get(path)
        uri = URI("#{API_BASE}#{path}")
        request = Net::HTTP::Get.new(uri)
        request["Content-Type"] = "application/json"

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

      def fetch_all_pages(response, original_payload)
        vulns = response["vulns"] || []
        page_token = response["next_page_token"]

        while page_token
          payload = original_payload.merge(page_token: page_token)
          response = post("/query", payload)
          vulns.concat(response["vulns"] || [])
          page_token = response["next_page_token"]
        end

        vulns
      end
    end
  end
end
