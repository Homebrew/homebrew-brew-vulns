# frozen_string_literal: true

require "json"
require "time"
require "fileutils"

module Brew
  module Vulns
    # Emits OSV-schema records for a `Homebrew` ecosystem describing CVEs that
    # homebrew-core formulae resolve via shipped patches.
    #
    # One record is written per (formula, vulnerability id) pair found in
    # `patches[].resolves`. The record states that the formula was affected up
    # to (but not including) the currently shipped version+revision; this is the
    # "fixed at or before what we ship today" approximation, since the precise
    # fix boundary requires homebrew-core git archaeology.
    #
    # Record shape follows the OSV 1.7 schema and mirrors the Debian DSA layout
    # (`upstream` listing the source CVE, `affected[].ranges` of type
    # `ECOSYSTEM`, `ecosystem_specific` carrying the patch detail).
    module OsvExport
      SCHEMA_VERSION = "1.7.3"
      ECOSYSTEM = "Homebrew"
      ID_PREFIX = "BREW"

      module_function

      def run(formulae, dir, client: OsvClient.new, now: Time.now.utc)
        FileUtils.mkdir_p(dir)
        written = []

        formulae.each do |formula|
          formula.resolved_vulnerability_ids.each do |vuln_id|
            upstream = fetch_upstream(client, vuln_id)
            record = record_for(formula, vuln_id, upstream: upstream, now: now)
            path = File.join(dir, "#{record[:id]}.json")
            File.write(path, JSON.pretty_generate(record))
            written << path
          end
        end

        written
      end

      def record_for(formula, vuln_id, upstream: nil, now: Time.now.utc)
        record = {
          schema_version: SCHEMA_VERSION,
          id:             record_id(formula, vuln_id),
          modified:       now.strftime("%Y-%m-%dT%H:%M:%SZ"),
          upstream:       [vuln_id],
          affected:       [affected_entry(formula, vuln_id)],
        }

        if upstream
          record[:summary] = upstream["summary"] if upstream["summary"]
          record[:details] = upstream["details"] if upstream["details"]
          record[:severity] = upstream["severity"] if upstream["severity"]
          record[:upstream] = ([vuln_id] + Array(upstream["aliases"])).uniq
          record[:references] = upstream["references"] if upstream["references"]
        end

        record
      end

      def record_id(formula, vuln_id)
        "#{ID_PREFIX}-#{formula.name}-#{vuln_id}"
      end

      def affected_entry(formula, vuln_id)
        {
          package: {
            ecosystem: ECOSYSTEM,
            name:      formula.name,
            purl:      "pkg:brew/#{formula.name}",
          },
          ranges: [
            {
              type:   "ECOSYSTEM",
              events: [
                { introduced: "0" },
                { fixed: formula.full_version },
              ],
            },
          ],
          ecosystem_specific: {
            fix:     "patch",
            patches: formula.patches_resolving(vuln_id).filter_map { |p| patch_ref(p) },
          },
        }
      end

      def patch_ref(patch)
        ref = {}
        ref[:type] = patch["type"] if patch["type"]
        ref[:url] = patch["url"] if patch["url"]
        ref[:file] = patch["file"] if patch["file"]
        ref[:apply] = patch["apply"] if patch["apply"]
        ref[:data] = true if patch["data"]
        ref.empty? ? nil : ref
      end

      def fetch_upstream(client, vuln_id)
        client.get_vulnerability(vuln_id)
      rescue OsvClient::Error
        nil
      end
    end
  end
end
